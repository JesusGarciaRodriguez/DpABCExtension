package eu.olympus.util.pseudonym;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.util.Pair;
import eu.olympus.util.model.PedersenBase;
import eu.olympus.util.model.PedersenCommitment;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.nio.charset.StandardCharsets;

import static eu.olympus.util.pseudonym.tools.Utils.newChallenge;


/**
 * Exposes high level abstraction of Range Proofs to be used by the OL prover (credMngmnt). Idea is to create a new RangeProver for each presentation process,
 * which generates all the necessary range proofs (and uses the same salt for base generation, for example the policy ID).
 */
public class PseudonymProver {
    private PairingBuilder builder;

    public PseudonymProver(PairingBuilder builder) {
        this.builder = builder;
    }

    /**
     * Generates a token for a pseudonym proof, i.e. generates a pseudonym and a proof that it matches the identity attribute in the credential
     *
     * @param TODO
     * @param context
     * @return
     */
    public Pair<PseudonymPredicateToken,PedersenCommitment> generatePseudonymPredicateToken(PedersenBase base, Attribute idAttribute, AttributeDefinition idDefinition, String scope, String context){
        //Compute the Pedersen Commitment on the identity attribute
        //System.err.println("PseudonymProver");
        ZpElement id  = builder.getZpElementFromAttribute(idAttribute,idDefinition);
        ZpElement open= builder.getRandomZpElement();
        PedersenCommitment V = new PedersenCommitment(base.getG(),base.getH(), id, open);
        // Compute scope base and pseudonym
        Group1Element g_scope=builder.hashGroup1ElementFromBytes(scope.getBytes(StandardCharsets.UTF_8));
        Group1Element p=g_scope.exp(id);
        //Randomness
        ZpElement r_id=builder.getRandomZpElement();
        ZpElement r_open=builder.getRandomZpElement();
        //Compute t_v,t_p
        Group1Element t_v=base.getG().exp(r_id).mul(base.getH().exp(r_open));
        Group1Element t_p=g_scope.exp(r_id);
        //Challenge
        ZpElement c=newChallenge(base.getG(), base.getH(), g_scope,V.getV(),p,t_v,t_p, context, builder);
        //Compute s_id, s_open
        ZpElement s_id=r_id.add(c.mul(id));
        ZpElement s_open=r_open.add(c.mul(open));
        //Return token and commitment
        PseudonymPredicateToken proofToken=new PseudonymPredicateToken(V.getV(),p,s_id,s_open,c);
    	return new Pair<>(proofToken,V);
    }

}
