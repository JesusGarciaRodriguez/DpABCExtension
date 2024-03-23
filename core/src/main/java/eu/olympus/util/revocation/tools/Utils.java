package eu.olympus.util.revocation.tools;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;

import static eu.olympus.util.Util.append;

import eu.olympus.util.multisign.MSverfKey;

public class Utils {
    public static ZpElement newChallenge(Group1Element com1, Group1Element com2, Group1Element t1, Group1Element t2, Group1Element g1, Group1Element h1, Group1Element g2, Group1Element h2, MSverfKey verfKey, String context, PairingBuilder builder) {
        byte[] bytes=com1.toBytes();
        bytes=append(bytes,com1.toBytes());
        bytes=append(bytes,com2.toBytes());
        bytes=append(bytes,t1.toBytes());
        bytes=append(bytes,t2.toBytes());
        bytes=append(bytes,g1.toBytes());
        bytes=append(bytes,h1.toBytes());
        bytes=append(bytes,g2.toBytes());
        bytes=append(bytes,h2.toBytes());
        bytes=append(bytes,verfKey.getEncoded());
        bytes=append(bytes,context.getBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

}
