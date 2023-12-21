package eu.olympus.unit.util.inspection;

import eu.olympus.model.*;
import eu.olympus.util.Pair;
import eu.olympus.util.inspection.InspectionPredicateToken;
import eu.olympus.util.inspection.InspectionProver;
import eu.olympus.util.inspection.model.ElGamalKey;
import eu.olympus.util.model.PedersenCommitment;
import eu.olympus.util.inspection.InspectionVerifier;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;

import eu.olympus.util.model.PedersenBase;
import org.junit.Test;

import static eu.olympus.util.inspection.InspectionPredicateVerificationResult.VALID;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class TestInspectionProofs {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static AttributeDefinition definitionInspectionAttribute=new AttributeDefinitionInteger("id","id",0,1000000);



    @Test
    public void testCorrectVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InspectionProver prover=new InspectionProver(builder);
        PedersenBase base=generateTestPedersenBase(builder);
        Attribute id=new Attribute(10312);
        ElGamalKey key=generateTestElGamalKey(builder);
        Pair<InspectionPredicateToken, PedersenCommitment> result=prover.generateInspectionPredicateToken(base,id,definitionInspectionAttribute,key);
        InspectionVerifier verifier=new InspectionVerifier(builder);
        assertSame(VALID, verifier.verifyInspectionPredicate(base, key, result.getFirst()));
    }



    @Test
    public void testFalseVerification() {
        String messageSalt="salt";
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        //TODO Try to modify token/key whatever and check that verification fails
    }


    private ElGamalKey generateTestElGamalKey(PairingBuilder builder) {
        return new ElGamalKey(builder.getGroup1Generator().exp(builder.getRandomZpElement()),builder.getGroup1Generator().exp(builder.getRandomZpElement()));
    }

    private PedersenBase generateTestPedersenBase(PairingBuilder builder) {
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element h=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new PedersenBase(g,h);
    }

}
