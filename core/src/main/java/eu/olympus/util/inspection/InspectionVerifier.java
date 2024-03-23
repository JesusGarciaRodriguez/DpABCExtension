package eu.olympus.util.inspection;

import static eu.olympus.util.inspection.tools.Utils.newChallenge;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.model.PedersenBase;
import eu.olympus.util.inspection.model.ElGamalKey;
import eu.olympus.util.inspection.model.ElGamalCiphertext;

public class InspectionVerifier {
    private PairingBuilder builder;

    public InspectionVerifier(PairingBuilder builder) {
        this.builder = builder;
    }
    
    /**
	 * @param commitmentBase : the base of the commitment scheme
	 * @param inspectionKey  : the public key under which the identity has been encrypted
	 * @param token          : the actual proof that the commitment and encryption are correct
	 * @param context
	 * @return
	 **/
    public InspectionPredicateVerificationResult verifyInspectionPredicate(PedersenBase commitmentBase, ElGamalKey inspectionKey, InspectionPredicateToken token, String context){
		//System.err.println("Inspection verifier");
    	ZpElement Sid = token.getSid();
    	ZpElement Srand = token.getSrand();
    	ZpElement Sopen = token.getSopen();
    	Group1Element V = token.getV();
    	ElGamalCiphertext E = token.getE();
    	ZpElement c = token.getChallenge();
    	
    	Group1Element g = commitmentBase.getG();
    	Group1Element h = commitmentBase.getH();
    	Group1Element base = inspectionKey.getBase();
    	Group1Element pk   = inspectionKey.getPK();
    	
        // Recompute t_V as t_V = g^Sid * h^Sopen * V^-c
    	Group1Element t_V = g.exp(Sid).mul(h.exp(Sopen)).mul(V.invExp(c));
    	
        // Recompute t_E as t_E = (base^Srand * E1^-c, base^Sid * pk^Srand * E2^-c)
    	Group1Element t_E1 = base.exp(Srand).mul(E.getE1().invExp(c));
    	Group1Element t_E2 = base.exp(Sid).mul(pk.exp(Srand)).mul(E.getE2().invExp(c));    	
    	ElGamalCiphertext t_E = new ElGamalCiphertext(t_E1,t_E2);
    	
        // Recompute challenge and check that it's the same
    	ZpElement cprime = newChallenge(V,E,t_V,t_E, context, builder);

    	return (c.equals(cprime)? InspectionPredicateVerificationResult.VALID : InspectionPredicateVerificationResult.INVALID);
    }


}