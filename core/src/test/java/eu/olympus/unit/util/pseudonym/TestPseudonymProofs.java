package eu.olympus.unit.util.pseudonym;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.util.Pair;
import eu.olympus.util.model.PedersenBase;
import eu.olympus.util.model.PedersenCommitment;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pseudonym.PseudonymPredicateToken;
import eu.olympus.util.pseudonym.PseudonymProver;
import eu.olympus.util.pseudonym.PseudonymVerifier;
import org.junit.Test;

import static eu.olympus.util.pseudonym.PseudonymPredicateVerificationResult.INVALID;
import static eu.olympus.util.pseudonym.PseudonymPredicateVerificationResult.VALID;
import static org.junit.Assert.assertSame;

public class TestPseudonymProofs {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static AttributeDefinition definitionInspectionAttribute=new AttributeDefinitionInteger("id","id",0,1000000);



    @Test
    public void testCorrectVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        String scope = "cs4eu:pseudonym:test";
        PseudonymProver prover=new PseudonymProver(builder);
        PedersenBase base=generateTestPedersenBase(builder);
        Attribute id=new Attribute(10312);
        Pair<PseudonymPredicateToken, PedersenCommitment> result=prover.generatePseudonymPredicateToken(base,id,definitionInspectionAttribute,scope);
        PseudonymVerifier verifier=new PseudonymVerifier(builder);
        assertSame(VALID, verifier.verifyPseudonymPredicate(base, result.getFirst(), scope));
    }



    @Test
    public void testFalseVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        String scope = "cs4eu:pseudonym:test";
        String anotherScope = "cs4eu:pseudonym:test2";
        PseudonymProver prover=new PseudonymProver(builder);
        PedersenBase base=generateTestPedersenBase(builder);
        Attribute id=new Attribute(10312);
        Attribute anotherId=new Attribute(20312);
        Pair<PseudonymPredicateToken, PedersenCommitment> result=prover.generatePseudonymPredicateToken(base,id,definitionInspectionAttribute,scope);
        Pair<PseudonymPredicateToken, PedersenCommitment> result2=prover.generatePseudonymPredicateToken(base,anotherId,definitionInspectionAttribute,anotherScope);
        PseudonymPredicateToken token=result.getFirst();
        PseudonymPredicateToken token2=result2.getFirst();
        PseudonymPredicateToken modifiedToken=new PseudonymPredicateToken(token2.getV(),token.getP(),token.getS_id(),token.getS_open(),token.getC());
        PseudonymPredicateToken modifiedToken2=new PseudonymPredicateToken(token.getV(),token2.getP(),token.getS_id(),token.getS_open(),token.getC());
        PseudonymVerifier verifier=new PseudonymVerifier(builder);
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, token, anotherScope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken, scope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken2, scope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken, anotherScope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken2, anotherScope));
    }


    private PedersenBase generateTestPedersenBase(PairingBuilder builder) {
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element h=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new PedersenBase(g,h);
    }

}
