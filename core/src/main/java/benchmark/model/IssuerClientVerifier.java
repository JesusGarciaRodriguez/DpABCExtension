package benchmark.model;

import eu.olympus.client.PSCredentialManagement;
import eu.olympus.server.ThresholdPSSharesGenerator;
import eu.olympus.verifier.PSPABCVerifier;

public class IssuerClientVerifier {
    ThresholdPSSharesGenerator issuer;
    PSCredentialManagement client;
    PSPABCVerifier verifier;

    public ThresholdPSSharesGenerator getIssuer() {
        return issuer;
    }

    public void setIssuer(ThresholdPSSharesGenerator issuer) {
        this.issuer = issuer;
    }

    public PSCredentialManagement getClient() {
        return client;
    }

    public void setClient(PSCredentialManagement client) {
        this.client = client;
    }

    public PSPABCVerifier getVerifier() {
        return verifier;
    }

    public void setVerifier(PSPABCVerifier verifier) {
        this.verifier = verifier;
    }

    public IssuerClientVerifier(ThresholdPSSharesGenerator issuer, PSCredentialManagement client, PSPABCVerifier verifier) {
        this.issuer = issuer;
        this.client = client;
        this.verifier = verifier;
    }
}
