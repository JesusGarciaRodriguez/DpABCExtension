package eu.olympus.client.interfaces;

import eu.olympus.model.PSCredential;

public interface CredentialStorage {

    void storeCredential(PSCredential credential);

    void storeRevocationCredential(PSCredential credential);

    PSCredential getCredential();

    PSCredential getRevocationCredential();

    boolean checkCredential();

    void deleteCredential();

    void deleteRevocationCredential();
}
