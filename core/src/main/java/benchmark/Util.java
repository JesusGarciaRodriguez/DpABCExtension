package benchmark;

import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.*;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSmessage;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSverfKey;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static benchmark.Main.*;

public class Util {

    public static final String REVOCATION_ATTR_ID = "revocation:attr";
    public static final String PSEUDONYM_ATTR_ID = "pseudonym:attr";
    public static final String INSPECTION_ATTR_ID = "inspection:attr";
    public static final String ID_ATTR_ID = "id:attr:";
    public static final String RANGE_ATTR_ID = "range:attr:";
    private static final String PAIRING_NAME="eu.olympus.util.pairingBLS461.PairingBuilderBLS461";
    public static final int REVOCATION_EPOCH = 1;


    protected static void generateAttrPredDef(Random random, Map<String,Attribute> allAttributes, Map<String,AttributeDefinition> allAttrDefinitions, List<Predicate> predicateList) {

        for (int i=0;i<nIdentityAttr;i++){
            String id = ID_ATTR_ID + i;
            allAttrDefinitions.put(id,new AttributeDefinitionString(id, id, 1,30));
            allAttributes.put(id,new Attribute("randomvalue"+ random.nextInt(10000)));
        }
        if(useRange){
            generateRangeAttrPredDef(random, allAttributes,  allAttrDefinitions, predicateList);
        }
        if(useInspection){
            String id = INSPECTION_ATTR_ID;
            allAttrDefinitions.put(id,new AttributeDefinitionInteger(id, id, 1,2147483647));
            predicateList.add(new Predicate(id, Operation.INSPECTION));
            allAttributes.put(id,new Attribute(randomInRangeInclusive(random, 1,2147483647)));
        }
        if(usePseudonym){
            String id = PSEUDONYM_ATTR_ID;
            allAttrDefinitions.put(id,new AttributeDefinitionInteger(id, id, 1,2147483647));
            predicateList.add(new Predicate(id, Operation.PSEUDONYM,new Attribute("scope")));
            allAttributes.put(id,new Attribute(randomInRangeInclusive(random, 1,2147483647)));
        }
        if(useRevocation){
            String id = REVOCATION_ATTR_ID;
            allAttrDefinitions.put(id,new AttributeDefinitionInteger(id, id, 1,2147483647));
            predicateList.add(new Predicate(id, Operation.REVOCATION,new Attribute(REVOCATION_EPOCH)));
            allAttributes.put(id,new Attribute(randomInRangeInclusive(random, 1,2147483647)));
        }
    }

    protected static void generateRangeAttrPredDef(Random random, Map<String,Attribute> allAttributes, Map<String,AttributeDefinition> allAttrDefinitions, List<Predicate> predicateList){
        for(int i=0;i<nRangeProof;i++){
            String id = RANGE_ATTR_ID + i;
            switch (sizeRangeBounds){
                case 2:
                case 3:
                case 4:
                case 5:
                    int min=1<<((1<<sizeRangeBounds-1)); // We use 3 steps to avoid int overflow for case 2^32 (alternatively use long for operations and then get int from result).
                    int max=min-1;
                    max+=1<<((1<<sizeRangeBounds-1));// Values in 1 max will be represented as is in Zp, with max=2^(2^(n-1)-1), thus using n bits
                    // As we use less than predicates, the upper bound of the predicate determines the number of bits used
                    allAttrDefinitions.put(id,new AttributeDefinitionInteger(id, id, 1,max));
                    allAttributes.put(id,new Attribute(randomInRangeInclusive(random,min,max-1)));
                    predicateList.add(new Predicate(id,Operation.LESSTHANOREQUAL,new Attribute(max-1)));
                    break;
                case 6: //For 2^64, we take advantage of Dates representations, in this case we force millisecond granularity to get big numbers
                    allAttrDefinitions.put(id,new AttributeDefinitionDate(id, id, "1970-01-01T00:00:00","2050-01-05T00:00:00",DateGranularity.MILLIS));
                    Date val=new Date(eu.olympus.util.Util.fromRFC3339UTC("2040-01-05T00:00:00").getTime()+randomInRangeInclusive(random, 1,10000000));
                    allAttributes.put(id,new Attribute(val));
                    predicateList.add(new Predicate(id,Operation.LESSTHANOREQUAL,new Attribute(eu.olympus.util.Util.fromRFC3339UTC("2050-01-04T00:00:00"))));
                    break;
                default:
                    System.err.println("Range predicate over 64 bits not supported as is");
                    System.exit(1);
            }
        }
    }

    protected static Pair<PSverfKey,PSCredential> generateRevocationElements(Map<String,AttributeDefinition> attrDefs, Map<String,Attribute> attrs) throws MSSetupException {
        //Create credentialGenerator.
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        Set<String> attrNames = new HashSet<>();
        attrNames.add(REVOCATION_ATTR_ID);
        PSms psScheme = new PSms();
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        MSpublicParam publicParams = psScheme.setup(1,auxArg, Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        //generate private key
        Pair<MSprivateKey, MSverfKey> keyPair = psScheme.kg();
        Map<String, ZpElement> attributesZpValues=new HashMap<>();
        Map<String,Attribute> attributeValues=new HashMap<>();
        Attribute attributeValue = attrs.get(REVOCATION_ATTR_ID);
        if(attributeValue!=null && attrDefs.get(REVOCATION_ATTR_ID).checkValidValue(attributeValue)){
            attributeValues.put(attrDefs.get(REVOCATION_ATTR_ID).getId().toLowerCase(),attributeValue);
            attributesZpValues.put(attrDefs.get(REVOCATION_ATTR_ID).getId().toLowerCase(),builder.getZpElementFromAttribute(attributeValue,attrDefs.get(REVOCATION_ATTR_ID)));
        }
        else{ //this branch should not be reached...
            throw new RuntimeException("Error, should not reach here, as revocation attribute should be found and valid");
        }
        MSsignature signature= psScheme.sign(keyPair.getFirst(),new PSmessage(attributesZpValues,builder.getZpElementFromEpoch(REVOCATION_EPOCH)));
        PSCredential revocationCredential = new PSCredential(REVOCATION_EPOCH,attributeValues,signature);
        return new Pair<>((PSverfKey)keyPair.getSecond(),revocationCredential);
    }

    static int randomInRangeInclusive(Random random,int min,int max){
        return random.nextInt(max-min)+min;
    }
}
