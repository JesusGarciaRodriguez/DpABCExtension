package eu.olympus.unit.util.rangeProofs;

import eu.olympus.model.*;
import eu.olympus.util.Util;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.rangeProof.RangePredicateVerificationResult;
import eu.olympus.util.rangeProof.RangeProver;
import eu.olympus.util.rangeProof.RangeVerifier;
import eu.olympus.util.model.PedersenBase;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestRangeProofs {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static AttributeDefinition definitionInt;
    private static AttributeDefinition definitionDate;
    private static AttributeDefinition definitionString;


    @BeforeClass
    public static void initializeDefinitions() {
        definitionDate=new AttributeDefinitionDate("url:DateAttribute","Date attr","1960-01-01T00:00:00","2000-09-01T00:00:00");
        definitionInt=new AttributeDefinitionInteger("url:IntegerWithNegatives","Int",-2000,10000);
        definitionString=new AttributeDefinitionString("url:String","String",0,2);
    }

    @Test
    public void testCorrectVerification() {
        String messageSalt="salt";
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        RangeProver prover=new RangeProver(messageSalt,builder);
        Attribute intValue=new Attribute(100);
        Predicate predInt1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,new Attribute(20));
        Predicate predInt2=new Predicate(definitionInt.getId(),Operation.LESSTHANOREQUAL,new Attribute(150));
        Predicate predInt3=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(99),new Attribute(101));
        PedersenBase baseInt=generateTestPedersenBase(builder);
        RangePredicateToken tokenInt1=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt1, "context");
        long start=System.currentTimeMillis();
        RangePredicateToken tokenInt2=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt2, "context"); // Commitment Map will not work well (though for this case it is not a problem)
        long finish=System.currentTimeMillis();
        RangePredicateToken tokenInt3=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt3, "context");
        Attribute dateValue=new Attribute(Util.fromRFC3339UTC("1990-06-04T00:00:01"));
        Predicate predDate1=new Predicate(definitionDate.getId(),Operation.GREATERTHANOREQUAL,new Attribute(Util.fromRFC3339UTC("1971-06-04T00:00:01")));
        Predicate predDate2=new Predicate(definitionDate.getId(),Operation.LESSTHANOREQUAL,new Attribute(Util.fromRFC3339UTC("1996-05-01T00:00:01")));
        Predicate predDate3=new Predicate(definitionDate.getId(),Operation.INRANGE,
                    new Attribute(Util.fromRFC3339UTC("1990-05-03T00:00:01")),new Attribute(Util.fromRFC3339UTC("1990-07-05T00:00:01")));
        PedersenBase baseDate=generateTestPedersenBase(builder);
        start=System.currentTimeMillis();
        RangePredicateToken tokenDate1=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate1, "context");
        finish=System.currentTimeMillis();
        RangePredicateToken tokenDate2=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate2, "context");
        RangePredicateToken tokenDate3=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate3, "context");
        RangeVerifier verifier=new RangeVerifier(messageSalt,builder);
        start=System.currentTimeMillis();
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt1,definitionInt,predInt1, "context"),is(RangePredicateVerificationResult.VALID));
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt1,definitionInt,predInt1, "fake-context"),is(RangePredicateVerificationResult.INVALID));
        finish=System.currentTimeMillis();
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt2,definitionInt,predInt2, "context"),is(RangePredicateVerificationResult.VALID));
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt3,definitionInt,predInt3, "context"),is(RangePredicateVerificationResult.VALID));
        start=System.currentTimeMillis();
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate1,definitionDate,predDate1, "context"),is(RangePredicateVerificationResult.VALID));
        finish=System.currentTimeMillis();
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate2,definitionDate,predDate2, "context"),is(RangePredicateVerificationResult.VALID));
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate3,definitionDate,predDate3, "context"),is(RangePredicateVerificationResult.VALID));
    }

    @Test
    public void testFalseVerification() {
        String messageSalt="salt";
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        RangeProver prover=new RangeProver(messageSalt,builder);
        Attribute intValue=new Attribute(10);
        Predicate predInt1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,new Attribute(15));
        Predicate predInt2=new Predicate(definitionInt.getId(),Operation.LESSTHANOREQUAL,new Attribute(7));
        Predicate predInt3=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(4),new Attribute(8));
        Predicate predInt4=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(12),new Attribute(16));
        PedersenBase baseInt=generateTestPedersenBase(builder);
        RangePredicateToken tokenInt1=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt1, "context");
        RangePredicateToken tokenInt2=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt2, "context"); // Commitment Map will not work well (though for this case it is not a problem)
        RangePredicateToken tokenInt3=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt3, "context");
        RangePredicateToken tokenInt4=prover.generateRangePredicateToken(baseInt,intValue,definitionInt,predInt4, "context");
        Attribute dateValue=new Attribute(Util.fromRFC3339UTC("1990-06-04T00:00:01"));
        Predicate predDate1=new Predicate(definitionDate.getId(),Operation.GREATERTHANOREQUAL,new Attribute(Util.fromRFC3339UTC("1991-06-04T00:00:01")));
        Predicate predDate2=new Predicate(definitionDate.getId(),Operation.LESSTHANOREQUAL,new Attribute(Util.fromRFC3339UTC("1986-05-01T00:00:01")));
        Predicate predDate3=new Predicate(definitionDate.getId(),Operation.INRANGE,
                new Attribute(Util.fromRFC3339UTC("1990-06-02T00:00:01")),new Attribute(Util.fromRFC3339UTC("1990-06-03T00:00:01")));
        PedersenBase baseDate=generateTestPedersenBase(builder);
        RangePredicateToken tokenDate1=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate1, "context");
        RangePredicateToken tokenDate2=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate2, "context");
        RangePredicateToken tokenDate3=prover.generateRangePredicateToken(baseDate,dateValue,definitionDate,predDate3, "context");
        RangeVerifier verifier=new RangeVerifier(messageSalt,builder);
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt1,definitionInt,predInt1, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt2,definitionInt,predInt2, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt3,definitionInt,predInt3, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseInt,tokenInt4,definitionInt,predInt4, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate1,definitionDate,predDate1, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate2,definitionDate,predDate2, "context"),is(RangePredicateVerificationResult.INVALID));
        assertThat(verifier.verifyRangePredicate(baseDate,tokenDate3,definitionDate,predDate3, "context"),is(RangePredicateVerificationResult.INVALID));
    }


        //Exceptions

    @Test
    public void testProverExceptions() {
        String messageSalt="salt";
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        RangeProver prover=new RangeProver(messageSalt,builder);
        Attribute intValue=new Attribute(10);
        Attribute dateValue=new Attribute(Util.fromRFC3339UTC("1996-06-02T00:00:01"));
        Predicate predInt1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,new Attribute(15));
        Predicate wrongPred=new Predicate(definitionInt.getId(),Operation.EQ,new Attribute(4));
        Predicate wrongPred2=new Predicate(definitionInt.getId()+"wrong",Operation.EQ,new Attribute(4));
        Predicate wrongPredNull1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,null);
        Predicate wrongPredNull2=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(15),null);
        Predicate wrongPredDateType1=new Predicate(definitionDate.getId(),Operation.GREATERTHANOREQUAL,new Attribute(15),null);
        Predicate wrongPredDateType2=new Predicate(definitionDate.getId(),Operation.INRANGE,new Attribute(Util.fromRFC3339UTC("1996-06-02T00:00:01")),new Attribute(16));
        Predicate wrongPredIntRange=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(16),new Attribute(15));
        Predicate wrongPredDateRange=new Predicate(definitionDate.getId(),Operation.INRANGE,
                new Attribute(Util.fromRFC3339UTC("1996-06-02T00:00:01")),new Attribute(Util.fromRFC3339UTC("1990-06-03T00:00:01")));
        PedersenBase base=generateTestPedersenBase(builder);
        try {
            prover.generateRangePredicateToken(base,intValue,definitionString,predInt1, "context");
            fail("Should throw IllegalArgumentException: wrong Attribute def");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,intValue,definitionInt,wrongPred, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,intValue,definitionInt,wrongPred2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,intValue,definitionInt,wrongPredNull1, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate null value");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,intValue,definitionInt,wrongPredNull2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate null extra");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,dateValue,definitionDate,wrongPredDateType1, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate type");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,dateValue,definitionDate,wrongPredDateType2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate type extra");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,dateValue,definitionInt,predInt1, "context");
            fail("Should throw IllegalArgumentException: wrong Attribute value type");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,dateValue,definitionDate,wrongPredDateRange, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate range date");
        }catch (IllegalArgumentException e){
        }
        try {
            prover.generateRangePredicateToken(base,intValue,definitionInt,wrongPredIntRange, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate range int");
        }catch (IllegalArgumentException e){
        }
    }

    @Test
    public void testVerifierExceptions() {
        String messageSalt="salt";
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        RangeVerifier verifier=new RangeVerifier(messageSalt,builder);
        Predicate predInt1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,new Attribute(15));
        Predicate wrongPred=new Predicate(definitionInt.getId(),Operation.EQ,new Attribute(4));
        Predicate wrongPred2=new Predicate(definitionInt.getId()+"wrong",Operation.EQ,new Attribute(4));
        Predicate wrongPredNull1=new Predicate(definitionInt.getId(),Operation.GREATERTHANOREQUAL,null);
        Predicate wrongPredNull2=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(15),null);
        Predicate wrongPredDateType1=new Predicate(definitionDate.getId(),Operation.GREATERTHANOREQUAL,new Attribute(15),null);
        Predicate wrongPredDateType2=new Predicate(definitionDate.getId(),Operation.INRANGE,new Attribute(Util.fromRFC3339UTC("1996-06-02T00:00:01")),new Attribute(16));
        Predicate wrongPredIntRange=new Predicate(definitionInt.getId(),Operation.INRANGE,new Attribute(16),new Attribute(15));
        Predicate wrongPredDateRange=new Predicate(definitionDate.getId(),Operation.INRANGE,
                new Attribute(Util.fromRFC3339UTC("1996-06-02T00:00:01")),new Attribute(Util.fromRFC3339UTC("1990-06-03T00:00:01")));
        AttributeDefinition wrongDef=new AttributeDefinitionString(definitionInt.getId(),"name",0,6);
        PedersenBase base=generateTestPedersenBase(builder);
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),wrongDef,predInt1, "context");
            fail("Should throw IllegalArgumentException: wrong Attribute def");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionInt,wrongPred, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionInt,wrongPred2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionInt,wrongPredNull1, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate null value");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionInt,wrongPredNull2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate null extra");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionDate,wrongPredDateType1, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate type");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionDate,wrongPredDateType2, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate type extra");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionDate,wrongPredDateRange, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate range date");
        }catch (IllegalArgumentException e){
        }
        try {
            verifier.verifyRangePredicate(base,new RangePredicateToken(null,null,null),definitionInt,wrongPredIntRange, "context");
            fail("Should throw IllegalArgumentException: wrong Predicate range int");
        }catch (IllegalArgumentException e){
        }
    }


    private PedersenBase generateTestPedersenBase(PairingBuilder builder) {
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element h=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new PedersenBase(g,h);
    }

}
