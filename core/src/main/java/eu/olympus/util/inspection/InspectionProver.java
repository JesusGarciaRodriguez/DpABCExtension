package eu.olympus.util.inspection;

import eu.olympus.model.*;
import eu.olympus.util.Pair;
import eu.olympus.util.inspection.model.*;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.model.PedersenCommitment;
import eu.olympus.util.model.PedersenBase;

import static eu.olympus.util.inspection.tools.Utils.newChallenge;


/**
 * Exposes high level abstraction of Range Proofs to be used by the OL prover (credMngmnt). Idea is to create a new RangeProver for each presentation process,
 * which generates all the necessary range proofs (and uses the same salt for base generation, for example the policy ID).
 */
public class InspectionProver {
    private PedersenCommitment generatedCommitment;
    private PairingBuilder builder;

    public InspectionProver(PairingBuilder builder){
        this.builder=builder;
    }

    /**
     * Generates a token for an inspectable proof, i.e., generates a commitment and an encryption of the identity and a proof that they are correct.
     *
     * @param base                Pedersen base for the proof
     * @param value               The attribute value of the identity to be encrypted
     * @param attributeDefinition The corresponding attribute definition. It has to be "numerical" (Integer or Date)
     * @param inspectionPK        public key of the inspection scheme to be used for encryption
     * @param context
     * @return
     */
    public Pair<InspectionPredicateToken,PedersenCommitment> generateInspectionPredicateToken(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, ElGamalKey inspectionPK, String context){
        //System.err.println("Inspection prover");
        ZpElement id    = builder.getZpElementFromAttribute(value,attributeDefinition);
    	ZpElement Rid   = builder.getRandomZpElement();

    	ZpElement open  = builder.getRandomZpElement();
    	ZpElement Ropen = builder.getRandomZpElement();

    	ZpElement rand  = builder.getRandomZpElement();
    	ZpElement Rrand = builder.getRandomZpElement();

    	
        PedersenCommitment V = new PedersenCommitment(base.getG(),base.getH(), id, open);     //V=X^id Y^open
    	ElGamalCiphertext  E = new ElGamalEncryption(inspectionPK, inspectionPK.getBase().exp(id), rand).getCiphertext(); //E encrypts base^id under randomness rand
    			
        PedersenCommitment t_V = new PedersenCommitment(base.getG(),base.getH(), Rid, Ropen);     
    	ElGamalCiphertext  t_E = new ElGamalEncryption(inspectionPK, inspectionPK.getBase().exp(Rid), Rrand).getCiphertext();  
 
		ZpElement c = newChallenge(V.getV(), E, t_V.getV(), t_E, context, builder );

    	// S_id = R_id + c*id
    	ZpElement Sid   = Rid.add(id.mul(c));
    	ZpElement Sopen = Ropen.add(open.mul(c));
    	ZpElement Srand = Rrand.add(rand.mul(c));


    	InspectionPredicateToken proofToken = new InspectionPredicateToken(Sid,Sopen,Srand,c,V.getV(),E);
    	
    	return new Pair<>(proofToken,V);
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
