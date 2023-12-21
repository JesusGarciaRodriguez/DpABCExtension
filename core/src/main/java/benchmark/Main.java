package benchmark;

import benchmark.model.IssuerClientVerifier;
import benchmark.storage.InMemoryPestoDatabase;
import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.ThresholdPSSharesGenerator;
import eu.olympus.server.interfaces.CredentialGenerator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.Pair;
import eu.olympus.util.inspection.model.ElGamalKey;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.verifier.PSPABCVerifier;
import eu.olympus.verifier.VerificationResult;
import eu.olympus.verifier.interfaces.PABCVerifier;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.hamcrest.core.Is;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static benchmark.Util.*;

public class Main {

    protected static final Integer DEFAULT_NREPETITIONS=10;
    protected static final Integer DEFAULT_NWARM=10;

    protected static final Integer DEFAULT_NIDATTR=3;
    protected static final Integer DEFAULT_NRANGE=1;
    protected static final Integer DEFAULT_SIZERANGEBOUNDS=-1;
    protected static final long DEFAULT_SEED = 12345678987654321L;

    protected static final long CRED_LIFETIME= 10000000000000L;


    protected static int nRepetitions,nWarmUp,nIdentityAttr,nRangeProof,sizeRangeBounds;
    protected static long seed;
    protected static boolean useRange,useInspection,usePseudonym,useRevocation;

    public static void main(String[] args) {
        ArgumentParser parser = ArgumentParsers.newFor("prog").build()
                .description("Benchmark p-ABC implementation");
        parser.addArgument("--range").type(Integer.class).help("include range proofs benchmark for 2^<n> bits").setDefault(DEFAULT_SIZERANGEBOUNDS);
        parser.addArgument("--inspection").action(Arguments.storeTrue()).help("include inspection benchmark");
        parser.addArgument("--revocation").action(Arguments.storeTrue()).help("include revocation benchmark");
        parser.addArgument("--pseudonym").action(Arguments.storeTrue()).help("include pseudonym benchmark");
        parser.addArgument("--rep").type(Integer.class).help("number of repetitions").setDefault(DEFAULT_NREPETITIONS);
        parser.addArgument("--warm").type(Integer.class).help("number of warmup iterations").setDefault(DEFAULT_NWARM);
        parser.addArgument("--nattr").type(Integer.class).help("number of identity attributes (outside revocation, range... i.e., just revealed/hidden) in the credential").setDefault(DEFAULT_NIDATTR);
        parser.addArgument("--nrangeattr").type(Integer.class).help("number of range proofs").setDefault(DEFAULT_NRANGE);
        parser.addArgument("--seed").type(Long.class).help("change seed to specific long value").setDefault(DEFAULT_SEED);
        try {
            Namespace res=parser.parseArgs(args);
            //System.out.println(res);
            nRepetitions=res.getInt("rep");
            nWarmUp=res.getInt("warm");
            nIdentityAttr=res.getInt("nattr");
            nRangeProof=res.getInt("nrangeattr");
            sizeRangeBounds=res.getInt("range");
            if(sizeRangeBounds!=DEFAULT_SIZERANGEBOUNDS)
                useRange=true;
            useInspection=res.getBoolean("inspection");
            usePseudonym=res.getBoolean("pseudonym");
            useRevocation=res.getBoolean("revocation");
            seed=res.getLong("seed");
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(0);
        }
        Random random=new Random(seed);
        Map<String,Attribute> allAttributes=new HashMap<>();
        Map<String,AttributeDefinition> allAttrDefinitions=new HashMap<>();
        List<Predicate> predicateList=new LinkedList<>();
        generateAttrPredDef(random,allAttributes,allAttrDefinitions,predicateList);
        Policy policy=new Policy(predicateList,"policyId");

        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        ElGamalKey inspectionKey=null;
        if(useInspection)
            inspectionKey=new ElGamalKey(builder.getGroup1Generator().exp(builder.getRandomZpElement()),builder.getGroup1Generator().exp(builder.getRandomZpElement()));
        Pair<PSverfKey,PSCredential> revocationElements= null;
        PSverfKey revocationKey = null;
        PSCredential revocationCredential = null;
        if(useRevocation) {
            try {
                revocationElements = generateRevocationElements(allAttrDefinitions, allAttributes);
            } catch (MSSetupException e) {
                throw new RuntimeException(e);
            }
            revocationKey = revocationElements.getFirst();
            revocationCredential = revocationElements.getSecond();
        }
        IssuerClientVerifier res= null;
        try {
            res = setupIsCliWithCredAndVerif(allAttributes, allAttrDefinitions, inspectionKey, revocationKey);
        } catch (SetupException | OperationFailedException | MSSetupException e) {
            throw new RuntimeException(e);
        }
        ThresholdPSSharesGenerator issuer=res.getIssuer();
        PSCredentialManagement client=res.getClient();
        if (useRevocation)
            client.setRevocationCredential(revocationCredential);
        PSPABCVerifier verifier=res.getVerifier();
        try {
            doBench(issuer,client,verifier,policy);
        } catch (TokenGenerationException e) {
            throw new RuntimeException(e);
        }
        //TODO We could do extra bench here, maybe without full "protocol", like Doing x Range proofs with different parameters, inrange vs lt/gt...
    }

    private static void doBench(ThresholdPSSharesGenerator issuer, PSCredentialManagement client, PSPABCVerifier verifier,Policy policy) throws TokenGenerationException {
        System.out.println("Starting presentation repetitions for the following configuration");
        String config="Nrepeats:"+nRepetitions+" NWarm:"+nWarmUp+" NIdAttr:"+nIdentityAttr+" Seed:"+seed+"\n";
        config+="Inspection:"+useInspection+" Revocation:"+useRevocation+" Pseudonym:"+usePseudonym;
        if (useRange)
            config+="\nRange:true With nRange:"+nRangeProof+" Size:"+sizeRangeBounds;
        else
            config+=" Range:"+false;
        System.out.println(config);
        double[] presentation_times=new double[nRepetitions];
        double[] verification_times=new double[nRepetitions];
        for(int i=0;i<nRepetitions+nWarmUp;i++){
            long start=System.currentTimeMillis();
            PresentationToken tok=client.generatePresentationToken(policy);
            long end=System.currentTimeMillis();
            //System.err.println("Prove i:"+i+" - "+(end-start)+" ms");
            if (i>=nWarmUp)
                presentation_times[i-nWarmUp]=(end-start);
            start=System.currentTimeMillis();
            if(verifier.verifyPresentationToken(tok.getEncoded(),policy)!= VerificationResult.VALID)
                throw new RuntimeException("Failed to verify presentation");
            end=System.currentTimeMillis();
            if (i>=nWarmUp)
                verification_times[i-nWarmUp]=(end-start);
            //System.err.println("Verify i:"+i+" - "+(end-start)+" ms");
        }
        double total_p=0;
        System.out.println("Presentation times: ");
        for(int i=0;i<nRepetitions;i++){
            if(i!=0)
                System.out.print(",");
            System.out.print(presentation_times[i]);
            total_p+=presentation_times[i];
        }
        System.out.println("\nMean: "+ total_p/(double)nRepetitions);

        double total_v=0;
        System.out.println("Verification times: ");
        for(int i=0;i<nRepetitions;i++){
            if(i!=0)
                System.out.print(",");
            System.out.print(verification_times[i]);
            total_v+=verification_times[i];
        }
        System.out.println("\nMean: "+ total_v/(double)nRepetitions);
    }

    private static IssuerClientVerifier setupIsCliWithCredAndVerif(Map<String, Attribute> allAttributes, Map<String, AttributeDefinition> allAttrDefinitions, ElGamalKey inspectionKey, PSverfKey revocationKey) throws SetupException, OperationFailedException, MSSetupException {
        PestoDatabase database= new InMemoryPestoDatabase();
        try {
            database.addUser("username",null,1);
            database.addAttributes("username", allAttributes);
        } catch (OperationFailedException e) {
            throw new RuntimeException(e);
        }
        //Create credentialGenerator module (only one signer)
        ThresholdPSSharesGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        PABCConfigurationImpl config = new PABCConfigurationImpl();
        config.setAttrDefinitions(new HashSet<>(allAttrDefinitions.values()));
        config.setSeed(Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        config.setLifetime(CRED_LIFETIME);
        config.setServers(new LinkedList<>());
        config.setAllowedTimeDifference(CRED_LIFETIME);
        if(useInspection)
            config.setEncodedInspectionKey(Base64.getEncoder().encodeToString(inspectionKey.getEncoded()));
        if(useRevocation)
            config.setEncodedRevocationKey(Base64.getEncoder().encodeToString(revocationKey.getEncoded()));
        credentialServerModule.setup(config);
        PabcPublicParameters publicParams=credentialServerModule.getPublicParam();
        MSverfKey verificationKey=credentialServerModule.getVerificationKeyShare();
        //Setup client
        CredentialStorage storage=new InMemoryCredentialStorage();
        long timestamp=System.currentTimeMillis();
        storage.storeCredential(credentialServerModule.createCredentialShare("username",timestamp));
        PSCredentialManagement credentialClientModule= new PSCredentialManagement(true,storage);
        credentialClientModule.setupForOffline(publicParams,verificationKey,Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        //Setup verifier
        PSPABCVerifier credentialVerifierModule = new PSPABCVerifier();
        credentialVerifierModule.setup(publicParams,verificationKey,Long.toString(seed).getBytes(StandardCharsets.UTF_8));
        return new IssuerClientVerifier(credentialServerModule,credentialClientModule,credentialVerifierModule);
    }


}
