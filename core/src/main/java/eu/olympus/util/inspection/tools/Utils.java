package eu.olympus.util.inspection.tools;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.inspection.model.ElGamalCiphertext;

import static eu.olympus.util.Util.append;

public class Utils {

    public static ZpElement newChallenge(Group1Element v, ElGamalCiphertext E, Group1Element t_v, ElGamalCiphertext t_E, String context, PairingBuilder builder) {
        byte[] bytes=v.toBytes();
        bytes=append(bytes,E.getE1().toBytes());
        bytes=append(bytes,E.getE2().toBytes());
        bytes=append(bytes,t_v.toBytes());
        bytes=append(bytes,t_E.getE1().toBytes());
        bytes=append(bytes,t_E.getE2().toBytes());
        bytes=append(bytes,context.getBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

}
