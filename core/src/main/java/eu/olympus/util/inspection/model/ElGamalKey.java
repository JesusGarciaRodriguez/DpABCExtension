package eu.olympus.util.inspection.model;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.psmultisign.PSauxArg;
import org.apache.commons.codec.binary.Base64;

//TODO check whether BLS461 is actually a valid group for ElGamal (DDH is required to hold to get CPA security)

public class ElGamalKey {
    private Group1Element base;
    private Group1Element pk;

    public ElGamalKey(Group1Element base, Group1Element pk) {
        this.base = base;
        this.pk   = pk;
    }

    public ElGamalKey(String encodedInspectionKey) throws InvalidProtocolBufferException {
        PabcSerializer.ElGamalKey protoPublicParam=PabcSerializer.ElGamalKey.parseFrom(Base64.decodeBase64(encodedInspectionKey));
        this.base=new Group1ElementBLS461(protoPublicParam.getBase());
        this.pk=new Group1ElementBLS461(protoPublicParam.getPk());
    }

    public Group1Element getBase() {
        return base;
    }

    public Group1Element getPK() {
        return pk;
    }

    public ElGamalKey(PabcSerializer.ElGamalKey e) {
        this.base=new Group1ElementBLS461(e.getBase());
        this.pk=new Group1ElementBLS461(e.getPk());
    }

    public PabcSerializer.ElGamalKey toProto() {
        return PabcSerializer.ElGamalKey.newBuilder()
                .setBase(base.toProto())
                .setPk(pk.toProto())
                .build();
    }

    public byte[] getEncoded() {
        return toProto().toByteArray();
    }


}
