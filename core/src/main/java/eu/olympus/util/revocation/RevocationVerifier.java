package eu.olympus.util.revocation;

import static eu.olympus.util.revocation.tools.Utils.newChallenge;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSmessage;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.util.psmultisign.PSzkTokenModified;
import eu.olympus.util.model.PedersenBase;

public class RevocationVerifier {
    private PairingBuilder builder;
    private List<AttributeDefinition> attributeDefinitions;
    private MS scheme;

    public RevocationVerifier(PairingBuilder builder, List<AttributeDefinition> attributeDefinitions, PSpublicParam schemePublicParameters, byte[] seed) throws SetupException{
        this.builder = builder;
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
     * @param TODO
     * @param context
     * @return
     **/
    public RevocationPredicateVerificationResult verifyRevocationPredicate(PedersenBase base, AttributeDefinition rhDefinition, RevocationPredicateToken token, MSverfKey revocationVerfKey, String context, int validEpoch){
        //System.err.println("Revocation verifier");
        if (token.getEpoch()<validEpoch)
            return RevocationPredicateVerificationResult.EXPIRED;

    	Group1Element V_RA      = token.getV_RA();
    	Group1Element V_issuer  = token.getV_issuer();
    	MSzkToken proof         = token.getProof();
        ZpElement S_open_RA     = token.getS_open_RA();
        ZpElement S_open_issuer = token.getS_open_issuer();
        ZpElement S_rh          = token.getS_rh();
        ZpElement c             = token.getC();
	
        if(!(proof instanceof PSzkTokenModified))
            return RevocationPredicateVerificationResult.INVALID;
        
        Map<String, ZpElement> revealedZpAttributes = new HashMap<>();

        MSmessage revealedAttributesMessage = new PSmessage(revealedZpAttributes,builder.getZpElementFromEpoch(token.getEpoch()));
        
        PedersenBase base_RA = new PedersenBase(((PSverfKey)revocationVerfKey).getVY().get(rhDefinition.getId().toLowerCase()), ((PSverfKey)revocationVerfKey).getVX());

        Map<String, Group1Element> commitments_RA = new HashMap<>();
        commitments_RA.put(rhDefinition.getId().toLowerCase(), V_RA);

        // check that the received commitment equality proof is correct
        // Recompute t_RA as t_RA = g_RA^S_rh * h^S_open_RA * V_RA^-c
    	Group1Element t_RA = base_RA.getG().exp(S_rh).mul(base_RA.getH().exp(S_open_RA)).mul(V_RA.invExp(c));
        // Recompute t_issuer as t_issuer = g_issuer^S_rh * h^S_open_issuer * V_issuer^-c
    	Group1Element t_issuer = base.getG().exp(S_rh).mul(base.getH().exp(S_open_issuer)).mul(V_issuer.invExp(c));
    	// Recompute challenge and check whether it is correct
    	ZpElement cprime = newChallenge(V_RA, V_issuer, t_RA, t_issuer, base_RA.getG(), base_RA.getH(), base.getG(), base.getH(), revocationVerfKey, context, builder);
    	boolean correctC = c.equals(cprime);
    	
        // verify "proof" (under the revocation authority's parameters)
		boolean verfResult = scheme.verifyZKtokenModified(proof, revocationVerfKey, context, revealedAttributesMessage, commitments_RA);
    	
		return (correctC && verfResult) ? RevocationPredicateVerificationResult.VALID : RevocationPredicateVerificationResult.INVALID;
    }


}