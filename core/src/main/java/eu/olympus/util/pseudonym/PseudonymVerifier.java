package eu.olympus.util.pseudonym;

import eu.olympus.util.model.PedersenBase;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.nio.charset.StandardCharsets;

import static eu.olympus.util.pseudonym.tools.Utils.newChallenge;

public class PseudonymVerifier {
    private PairingBuilder builder;

    public PseudonymVerifier(PairingBuilder builder) {
        this.builder = builder;
    }

    /**
     * @param TODO
     * @return
     **/
    public PseudonymPredicateVerificationResult verifyPseudonymPredicate(PedersenBase base, PseudonymPredicateToken token, String scope){
        //System.err.println("PseudonymVerifier");
        //Compute the scope base
        Group1Element g_scope=builder.hashGroup1ElementFromBytes(scope.getBytes(StandardCharsets.UTF_8));
        //Recompute t_v, t_p
        Group1Element t_v=base.getG().exp(token.getS_id()).mul(base.getH().exp(token.getS_open())).mul(token.getV().invExp(token.getC()));
        Group1Element t_p=g_scope.exp(token.getS_id()).mul(token.getP().invExp(token.getC()));
        //Recompute challenge
        ZpElement newC=newChallenge(base.getG(), base.getH(), g_scope,token.getV(),token.getP(),t_v,t_p,builder);
        return newC.equals(token.getC()) ? PseudonymPredicateVerificationResult.VALID: PseudonymPredicateVerificationResult.INVALID;
    }


}