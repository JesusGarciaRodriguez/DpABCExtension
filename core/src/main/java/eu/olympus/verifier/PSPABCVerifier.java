package eu.olympus.verifier;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.util.Pair;
import eu.olympus.util.inspection.InspectionPredicateVerificationResult;
import eu.olympus.util.inspection.InspectionVerifier;
import eu.olympus.util.inspection.model.ElGamalKey;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.pseudonym.PseudonymPredicateVerificationResult;
import eu.olympus.util.pseudonym.PseudonymVerifier;
import eu.olympus.util.psmultisign.*;
import eu.olympus.util.rangeProof.RangePredicateVerificationResult;
import eu.olympus.util.rangeProof.RangeVerifier;
import eu.olympus.util.model.PedersenBase;
import eu.olympus.util.revocation.RevocationPredicateVerificationResult;
import eu.olympus.util.revocation.RevocationVerifier;
import eu.olympus.verifier.interfaces.PABCVerifier;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class PSPABCVerifier implements PABCVerifier {

    private MS multiSignatureScheme;
    private Set<AttributeDefinition> attributeDefinitions;
    private Map<String,AttributeDefinition> attrDefMap; // Key will have the AttrDefId in lower case
    private MSpublicParam schemePublicParameters;
    private MSverfKey olympusVerificationKey;
    private PairingBuilder builder;
    private ElGamalKey inspectionKey;
    private PSverfKey revocationVerfKey;

    public void setup(List<? extends PabcIdP> servers, byte[] seed) throws OperationFailedException {
        PabcPublicParameters publicParameters = servers.get(0).getPabcPublicParam();
        try {
            schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException("Could not retrieve scheme public param");
        }
        attributeDefinitions=publicParameters.getAttributeDefinitions();
        if(!checkAttributeDefinitions())
            throw new IllegalArgumentException("Conflicting sets of attribute names");
        multiSignatureScheme = new PSms();
        PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
        try {
            multiSignatureScheme.setup(schemePublicParameters.getN(), auxArg, seed);
            builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
            builder.seedRandom(seed);
        } catch (Exception e) {//TODO Handle exception
            throw new RuntimeException("Could not create scheme", e);
        }
        MSverfKey[] verificationKeySharesArray = new MSverfKey[servers.size()];
        for (int i = 0; i < servers.size(); i++) {
            verificationKeySharesArray[i] = servers.get(i).getPabcPublicKeyShare(); //TODO Concurrent
        }
        this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(e-> e.getId().toLowerCase(),
                Function.identity()));
        try {
            this.inspectionKey = publicParameters.getEncodedInspectionKey()==null ? null : new ElGamalKey(publicParameters.getEncodedInspectionKey());
        } catch (InvalidProtocolBufferException e) {
            //No ElGammalInspection key set
            this.inspectionKey = null;
            //throw new SetupException("Could not retrieve inspection key",e);
        }
        try {
            this.revocationVerfKey = publicParameters.getEncodedRevocationKey()==null ? null : new PSverfKey(publicParameters.getEncodedRevocationKey());
        } catch (InvalidProtocolBufferException e) {
            //No ElGammalInspection key set
            this.revocationVerfKey = null;
            //throw new SetupException("Could not retrieve inspection key",e);
        }
    }

    public void setup(PabcPublicParameters publicParameters, MSverfKey olympusVerificationKey, byte[] seed) throws MSSetupException {
        attributeDefinitions=publicParameters.getAttributeDefinitions();
        try {
            schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalArgumentException("Could not retrieve scheme public param");
        }
        multiSignatureScheme=new PSms();
        PSauxArg auxArg= (PSauxArg) schemePublicParameters.getAuxArg();
        multiSignatureScheme.setup(schemePublicParameters.getN(),auxArg, seed); //TODO Treat exception instead of throwing it?
        if(!checkAttributeDefinitions())
            throw new IllegalArgumentException("Conflicting sets of attribute names");
        this.olympusVerificationKey=olympusVerificationKey;
        try {
            builder=(PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
            builder.seedRandom(seed);
        } catch (Exception e) {
            throw new RuntimeException(e);
            //Should never reach this point, as the newInstance method must be successful for setting up the scheme
        }
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(e-> e.getId().toLowerCase(),
                Function.identity()));
        try {
            this.inspectionKey = publicParameters.getEncodedInspectionKey()==null ? null : new ElGamalKey(publicParameters.getEncodedInspectionKey());
        } catch (InvalidProtocolBufferException e) {
            //No ElGammalInspection key set
            this.inspectionKey = null;
            //throw new SetupException("Could not retrieve inspection key",e);
        }
        try {
            this.revocationVerfKey = publicParameters.getEncodedRevocationKey()==null ? null : new PSverfKey(publicParameters.getEncodedRevocationKey());
        } catch (InvalidProtocolBufferException e) {
            //No ElGammalInspection key set
            this.revocationVerfKey = null;
            //throw new SetupException("Could not retrieve inspection key",e);
        }
    }

    public Pair<PabcPublicParameters,MSverfKey> getPublicParams(){
        if(multiSignatureScheme==null)
            throw new IllegalStateException("No setup was performed");
        return new Pair<>(new PabcPublicParameters(attributeDefinitions,schemePublicParameters.getEncoded()),olympusVerificationKey);
    }

    @Override
    public VerificationResult verifyPresentationToken(String token, Policy policy) {
        if(multiSignatureScheme==null) {
            throw new IllegalStateException("It is necessary to run setup before using this method");
        }
        try {
            PresentationToken reconstructedToken=new PresentationToken(token);
            Set<String> attributesToReveal = new HashSet<>();
            Set<String> attributesForRange = new HashSet<>();
            List<Predicate> rangePredicates = new LinkedList<>();
            Predicate inspectionPredicate = null;
            Predicate revocationPredicate = null;
            Predicate pseudonymPredicate = null;
    		for(Predicate p: policy.getPredicates()) {
    			if(p.getOperation() == Operation.REVEAL) {
    				attributesToReveal.add(p.getAttributeName().toLowerCase());
    			} else if (p.getOperation() == Operation.INRANGE || p.getOperation() == Operation.GREATERTHANOREQUAL || p.getOperation() == Operation.LESSTHANOREQUAL) {
                    rangePredicates.add(p);
                    attributesForRange.add(p.getAttributeName().toLowerCase());
                } else if (p.getOperation() == Operation.INSPECTION) {
                	inspectionPredicate = p;
                } else if (p.getOperation() == Operation.REVOCATION) {
                	revocationPredicate = p;
                }else if (p.getOperation() == Operation.PSEUDONYM) {
                    pseudonymPredicate = p;
                } else {
    				throw new IllegalArgumentException("Could not satisfy policy: "+p.getOperation()+" is not supported for dp-ABC");
    			}
    		}
            if(!attrDefMap.keySet().containsAll(attributesToReveal) || !attrDefMap.keySet().containsAll(attributesForRange))
                throw new IllegalArgumentException("Wrong policy: Attributes requested are not fit for the setup of the verifier");
            if (attributesForRange.size() != rangePredicates.size())
                throw new IllegalArgumentException("Wrong policy: Repeated attribute ID in different range predicates");
            if(!reconstructedToken.getRevealedAttributes().keySet().containsAll(attributesToReveal))
                return VerificationResult.POLICY_NOT_FULFILLED;
            if(reconstructedToken.getEpoch()<System.currentTimeMillis())
                return VerificationResult.BAD_TIMESTAMP;

            Map<String, ZpElement> revealedZpAttributes=new HashMap<>();
            Map<String,Attribute> revealedAttributes=reconstructedToken.getRevealedAttributes();
            for(String attr:revealedAttributes.keySet()){
                Attribute attrValue=revealedAttributes.get(attr);
                AttributeDefinition def=attrDefMap.get(attr);//Already checked that they are all present, also indexed by lowerCase id
                revealedZpAttributes.put(attr,builder.getZpElementFromAttribute(attrValue,def));
            }
            MSmessage revealedAttributesMessage=new PSmessage(revealedZpAttributes,builder.getZpElementFromEpoch(reconstructedToken.getEpoch()));
            if(rangePredicates.isEmpty() && inspectionPredicate == null && revocationPredicate == null && pseudonymPredicate==null){
                if(!(reconstructedToken.getZkToken() instanceof PSzkToken))
                    return VerificationResult.INVALID_SIGNATURE;
                if(!multiSignatureScheme.verifyZKtoken(reconstructedToken.getZkToken(),olympusVerificationKey,policy.getPolicyId(), revealedAttributesMessage)) {
                    return VerificationResult.INVALID_SIGNATURE;
                }
                return VerificationResult.VALID;
            } else {
                if(!(reconstructedToken.getZkToken() instanceof PSzkTokenModified))
                    return VerificationResult.INVALID_SIGNATURE;

                PSverfKey key = (PSverfKey) olympusVerificationKey;

                Map<String, Group1Element> Vp = new HashMap<>();
                
            	if (!rangePredicates.isEmpty()) {
	                if(!reconstructedToken.getRangeTokens().keySet().equals(attributesForRange))
	                    return VerificationResult.INVALID_SIGNATURE;
	                Vp.putAll(reconstructedToken.getRangeTokens().entrySet().stream().collect(Collectors.toMap(e -> e.getKey(),e -> e.getValue().getCommitV())));

	                RangeVerifier verifier=new RangeVerifier(policy.getPolicyId(),builder);
	                for(Predicate p:rangePredicates){
	                    String attrId=p.getAttributeName().toLowerCase();
	                    AttributeDefinition def=attrDefMap.get(attrId);//Already checked that they are all present
	                    PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
	                    if(verifier.verifyRangePredicate(base,reconstructedToken.getRangeTokens().get(attrId),def,p)== RangePredicateVerificationResult.INVALID)
	                        return VerificationResult.INVALID_SIGNATURE;
	                }
            	}
            	
            	if (inspectionPredicate != null) {
                    String attrId = inspectionPredicate.getAttributeName().toLowerCase();
                    AttributeDefinition definition = attrDefMap.get(attrId);
                	InspectionVerifier inspectionVerifier = new InspectionVerifier(builder);
                	
                	PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
                    
                	Vp.put(attrId, reconstructedToken.getInspectionToken().getV());
                	
                    InspectionPredicateVerificationResult inspectionResult = inspectionVerifier.verifyInspectionPredicate(base, inspectionKey, reconstructedToken.getInspectionToken());
                    if (inspectionResult != InspectionPredicateVerificationResult.VALID) {
                    	return VerificationResult.INVALID_SIGNATURE;
                    }
            	}

                if (pseudonymPredicate != null) {
                    String attrId = pseudonymPredicate.getAttributeName().toLowerCase();
                    AttributeDefinition definition = attrDefMap.get(attrId);
                    PseudonymVerifier pseudonymVerifier = new PseudonymVerifier(builder);

                    PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X

                    Vp.put(attrId, reconstructedToken.getPseudonymToken().getV());
                    String scope=(String)pseudonymPredicate.getValue().getAttr(); //TODO Maybe do some check
                    PseudonymPredicateVerificationResult pseudonymResult = pseudonymVerifier.verifyPseudonymPredicate(base, reconstructedToken.getPseudonymToken(), scope);
                    if (pseudonymResult != PseudonymPredicateVerificationResult.VALID) {
                        return VerificationResult.INVALID_SIGNATURE;
                    }
                }
            	
            	if (revocationPredicate != null) {
            		String attrId = revocationPredicate.getAttributeName().toLowerCase();
                    AttributeDefinition definition = attrDefMap.get(attrId);
                    PSpublicParam revocationPP=new PSpublicParam(1,new PSauxArg(((PSauxArg)schemePublicParameters.getAuxArg()).getPairingName(),Collections.singleton(attrId.toLowerCase())));
                    RevocationVerifier revocationVerifier = new RevocationVerifier(builder, new ArrayList<>(attributeDefinitions), revocationPP,"Some seed".getBytes());
                	PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
            		
                	Vp.put(attrId, reconstructedToken.getRevocationToken().getV_issuer());
                	
                	Integer expectedEpoch = (Integer) revocationPredicate.getValue().getAttr();
                	RevocationPredicateVerificationResult revocationResult = revocationVerifier.verifyRevocationPredicate(base,definition, reconstructedToken.getRevocationToken(), revocationVerfKey, policy.getPolicyId(), expectedEpoch);

                    if (revocationResult != RevocationPredicateVerificationResult.VALID) {
                    	return VerificationResult.INVALID_SIGNATURE;
                    }
            	}
            	
                if(!multiSignatureScheme.verifyZKtokenModified(reconstructedToken.getZkToken(),olympusVerificationKey,policy.getPolicyId(), revealedAttributesMessage,Vp))
                    return VerificationResult.INVALID_SIGNATURE;
            	
                return VerificationResult.VALID;
            }
        } catch (InvalidProtocolBufferException e) {
            return VerificationResult.INVALID_SIGNATURE; //TODO Maybe new type: INVALID_TOKEN (and other types for more info e.g: invalid policy )?
        } catch (SetupException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean checkAttributeDefinitions() {
        Set<String> attrIds=attributeDefinitions.stream().map(e->e.getId().toLowerCase()).collect(Collectors.toSet());
        return attrIds.equals(((PSauxArg) schemePublicParameters.getAuxArg()).getAttributes());
    }

}
