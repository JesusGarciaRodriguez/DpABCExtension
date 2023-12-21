package eu.olympus.util.inspection;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.inspection.model.ElGamalCiphertext;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class InspectionPredicateToken {
    private ZpElement Sid;
    private ZpElement Sopen;
    private ZpElement Srand;
    
    private ZpElement c;
    
    private Group1Element V;
    private ElGamalCiphertext E;
    
    public InspectionPredicateToken(ZpElement Sid, ZpElement Sopen, ZpElement Srand, ZpElement c, Group1Element V, ElGamalCiphertext E) {
        this.Sid = Sid;
        this.Sopen = Sopen;
        this.Srand = Srand;
        this.c = c;
        this.V = V;
        this.E = E;
    }

    public InspectionPredicateToken(PabcSerializer.InspectionPredicateToken inspectionPredToken) {
        this.Sid   = new ZpElementBLS461(inspectionPredToken.getSid());
        this.Sopen = new ZpElementBLS461(inspectionPredToken.getSopen());
        this.Srand = new ZpElementBLS461(inspectionPredToken.getSrand());
        this.c     = new ZpElementBLS461(inspectionPredToken.getC());
        this.V     = new Group1ElementBLS461(inspectionPredToken.getV());
        this.E     = new ElGamalCiphertext(inspectionPredToken.getE());
    }

    public Group1Element getV() {
        return V;
    }

    public ZpElement getSid() {
        return Sid;
    }

    public ZpElement getSopen() {
        return Sopen;
    }

    public ZpElement getSrand() {
        return Srand;
    }

    public ZpElement getChallenge() {
        return c;
    }

    public ElGamalCiphertext getE() {
        return E;
    }

    public PabcSerializer.InspectionPredicateToken toProto() {
        return PabcSerializer.InspectionPredicateToken.newBuilder()
                .setV(V.toProto())
                .setE(E.toProto())
                .setC(c.toProto())
                .setSid(Sid.toProto())
                .setSopen(Sopen.toProto())
                .setSrand(Srand.toProto())
                .build();
    }
}
