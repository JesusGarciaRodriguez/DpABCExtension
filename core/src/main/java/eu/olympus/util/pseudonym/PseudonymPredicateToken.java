package eu.olympus.util.pseudonym;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSzkTokenModified;

public class PseudonymPredicateToken {
	private final Group1Element V;
    private final Group1Element P;
    private final ZpElement s_id, s_open, c;

    public PseudonymPredicateToken(Group1Element v, Group1Element p, ZpElement s_id, ZpElement s_open, ZpElement c) {
        V = v;
        P = p;
        this.s_id = s_id;
        this.s_open = s_open;
        this.c = c;
    }

    public Group1Element getP() {
        return P;
    }

    public ZpElement getS_id() {
        return s_id;
    }

    public ZpElement getS_open() {
        return s_open;
    }

    public ZpElement getC() {
        return c;
    }

    public PseudonymPredicateToken(PabcSerializer.PseudonymPredicateToken pseudonymPredicateToken) {
        this.V = new Group1ElementBLS461(pseudonymPredicateToken.getV());
        this.P = new Group1ElementBLS461(pseudonymPredicateToken.getP());
        this.s_id =new ZpElementBLS461(pseudonymPredicateToken.getSId());
        this.s_open =new ZpElementBLS461(pseudonymPredicateToken.getSOpen());
        this.c =new ZpElementBLS461(pseudonymPredicateToken.getC());

    }

    public Group1Element getV() {
		return V;
	}


    public PabcSerializer.PseudonymPredicateToken toProto() {
        return PabcSerializer.PseudonymPredicateToken.newBuilder()
                .setV(V.toProto())
                .setP(P.toProto())
                .setSId(s_id.toProto())
                .setSOpen(s_open.toProto())
                .setC(c.toProto())
                .build();
    }
}
