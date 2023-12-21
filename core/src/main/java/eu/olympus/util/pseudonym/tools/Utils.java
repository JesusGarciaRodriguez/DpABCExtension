package eu.olympus.util.pseudonym.tools;

import eu.olympus.util.inspection.model.ElGamalCiphertext;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;

import static eu.olympus.util.Util.append;

public class Utils {

    public static ZpElement newChallenge(Group1Element g, Group1Element h, Group1Element g_scope, Group1Element v, Group1Element p, Group1Element t_v, Group1Element t_p, PairingBuilder builder) {
        byte[] bytes=g.toBytes();
        bytes=append(bytes,h.toBytes());
        bytes=append(bytes,v.toBytes());
        bytes=append(bytes,g_scope.toBytes());
        bytes=append(bytes,p.toBytes());
        bytes=append(bytes,t_v.toBytes());
        bytes=append(bytes,t_p.toBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

}
