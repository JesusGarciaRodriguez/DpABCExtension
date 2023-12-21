package eu.olympus.util.inspection.model;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.inspection.model.ElGamalKey;
import eu.olympus.util.inspection.model.ElGamalCiphertext;


/**
 * ElGamal Encryption E = (base^rand, message * pk^rand)
 */
public class ElGamalEncryption {
    private ElGamalKey key;
    private ElGamalCiphertext E;
    private ZpElement rand;
    private Group1Element message;

    public ElGamalEncryption(ElGamalKey key, Group1Element message, ZpElement rand) {
        this.key = key;
        this.rand= rand;
        this.message = message;
        Group1Element base = key.getBase();
        Group1Element pk   = key.getPK();

        this.E = new ElGamalCiphertext(base.exp(rand), message.mul(pk.exp(rand)));
    }

    public ElGamalCiphertext getCiphertext() {
        return E;
    }

    public ElGamalKey getKey() {
        return key;
    }

    public ZpElement getRand() {
        return rand;
    }

    public Group1Element getMessage() {
        return message;
    }
}
