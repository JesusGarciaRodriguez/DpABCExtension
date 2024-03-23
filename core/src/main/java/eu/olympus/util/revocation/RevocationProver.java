package eu.olympus.util.revocation;

import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.multisign.MSsignature;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSmessage;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.util.model.PedersenCommitment;
import eu.olympus.util.model.PedersenBase;

import static eu.olympus.util.revocation.tools.Utils.newChallenge;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Exposes high level abstraction of Range Proofs to be used by the OL prover (credMngmnt). Idea is to create a new RangeProver for each presentation process,
 * which generates all the necessary range proofs (and uses the same salt for base generation, for example the policy ID).
 */
public class RevocationProver {
    private PedersenCommitment generatedCommitment;
    private PairingBuilder builder;
    private MS scheme;
    private List<AttributeDefinition> attributeDefinitions;
    
    public RevocationProver(PairingBuilder builder, List<AttributeDefinition> attributeDefinitions, PSpublicParam schemePublicParameters, byte[] seed) throws SetupException{
        //System.err.println("Revocation prover");
        this.builder=builder;
        this.attributeDefinitions = attributeDefinitions;
        
        this.scheme = new PSms();
		int numberOfIdPs = schemePublicParameters.getN();
		PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
		try {
			scheme.setup(numberOfIdPs, auxArg, seed);
		} catch (MSSetupException e) {
			throw new SetupException("Wrong public parameters", e);
		}
    }
    /**
     * Generates a token for an inspectable proof, i.e., generates a commitment and an encryption of the identity and a proof that they are correct.
     *
     * @param TODO
     * @param context
     * @return
     */
    public Pair<RevocationPredicateToken,PedersenCommitment> generateRevocationPredicateToken(PedersenBase base, AttributeDefinition rhDefinition, PSCredential revocationCredential, MSverfKey revocationVerfKey, String context){
    	Attribute revocationHandle = revocationCredential.getElement(rhDefinition.getId().toLowerCase());

    	if (!rhDefinition.checkValidValue(revocationHandle)) {
            throw new IllegalArgumentException("Invalid revocation handle (check range)!");
    	}
    	
    	ZpElement rh  = builder.getZpElementFromAttribute(revocationHandle,rhDefinition);

    	// Compute a Pedersen Commitment on the attribute rh which will be used to link to 
    	// the main presentation, i.e., this commitment uses the issuer's base elements
    	ZpElement open_issuer       = builder.getRandomZpElement();
        PedersenCommitment V_issuer = new PedersenCommitment(base.getG(),base.getH(), rh, open_issuer);     //V=X^rh Y^open
    	
        // We also need an additional Pedersen commitment that will be used to link to the
        // presentation of the revocationCredential. For this, we get the base elements
        // from the public key of the revocation authority
        PedersenBase base_RA = new PedersenBase(((PSverfKey)revocationVerfKey).getVY().get(rhDefinition.getId().toLowerCase()), ((PSverfKey)revocationVerfKey).getVX());
		ZpElement open_RA = builder.getRandomZpElement();
		PedersenCommitment V_RA = new PedersenCommitment(base_RA.getG(), base_RA.getH(), rh, open_RA);
        
        // the epoch of the revocation authority has to be revealed, but is revealed by default
        // (will be checked by the verifier to ensure that the signature is fresh enough)
        Set<String> revocationAttributesToReveal = new HashSet<>();

       	// the revocation handle itself needs to be committed to
       	// (is used to bridge to the main presentation proof)
    	Map<String, PedersenCommitment> commitments_RA = new HashMap<>();
        commitments_RA.put(rhDefinition.getId().toLowerCase(), V_RA);

        Map<String, ZpElement> attributeZpValues = new HashMap<>();
        attributeZpValues.put(rhDefinition.getId().toLowerCase(), rh);

        MSmessage signedAttributes = new PSmessage(attributeZpValues, builder.getZpElementFromEpoch(revocationCredential.getEpoch()));
        
		// Call the modified zkToken for PS signatures to prove knowledge of
    	// a PS signature on (epoch, rh), where epoch is treated as a disclosed
    	// attribute and rh is kept private. 
    	MSsignature revocationSignature = revocationCredential.getSignature();

    	// Extend proof token to actually prove equality of what is committed to in V_RA and V_issuer
    	ZpElement R_open_RA     = builder.getRandomZpElement();
    	ZpElement R_open_issuer = builder.getRandomZpElement();
    	ZpElement R_rh          = builder.getRandomZpElement();
    	
    	// T_RA = commitment (base_RA,r_rh,r_open_RA)
    	// T_issuer = commitment (base_issuer,r_rh,r_open_issuer)
        PedersenCommitment T_RA     = new PedersenCommitment(base_RA.getG(), base_RA.getH(), R_rh, R_open_RA);
        PedersenCommitment T_issuer = new PedersenCommitment(base.getG(), base.getH(), R_rh, R_open_issuer);

    	ZpElement c = newChallenge(V_RA.getV(), V_issuer.getV(), T_RA.getV(), T_issuer.getV(), base_RA.getG(), base_RA.getH(), base.getG(), base.getH(), revocationVerfKey, context, builder);
    	
    	
    	ZpElement S_open_RA     = R_open_RA.add(open_RA.mul(c));
    	ZpElement S_open_issuer = R_open_issuer.add(open_issuer.mul(c)); 
    	ZpElement S_rh          = R_rh.add(rh.mul(c));
    	
    	
    	// TODO: add c, S_open_RA, S_open_issuer, S_rh to the token
    	MSzkToken token = scheme.presentZKtokenModified(revocationVerfKey,revocationAttributesToReveal,commitments_RA, signedAttributes, context, revocationSignature);

    	RevocationPredicateToken proofToken = new RevocationPredicateToken(V_RA.getV(),V_issuer.getV(),token,S_open_RA,S_open_issuer,S_rh,c,revocationCredential.getEpoch());
            	
    	return new Pair<>(proofToken,V_issuer);
    }


    /**
     * After the proof has been executed with this Prover instance, you can retrieve the commitment for the attribute so you can use it as
     * needed (e.g., for linking proof...). 
     * @return
     */
    public PedersenCommitment getGeneratedCommitment() {
        return generatedCommitment;
    }
}
