package eu.olympus.util.revocation;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSzkToken;
import eu.olympus.util.psmultisign.PSzkTokenModified;

public class RevocationPredicateToken {
	private Group1Element V_RA;
	private Group1Element V_issuer;
	private MSzkToken proof;
	private ZpElement S_open_RA;
	private ZpElement S_open_issuer;
	private ZpElement S_rh;
	private ZpElement c;
	private long revocationEpoch;
    
	public RevocationPredicateToken(Group1Element V_RA, Group1Element V_issuer, MSzkToken proof, ZpElement S_open_RA, ZpElement S_open_issuer, ZpElement S_rh, ZpElement c, long revocationEpoch) {
        this.proof = proof;
        this.V_RA = V_RA;
        this.V_issuer = V_issuer;
        this.S_open_RA = S_open_RA;
        this.S_open_issuer = S_open_issuer;
        this.S_rh = S_rh;
        this.c = c;
        this.revocationEpoch = revocationEpoch;
    }

    public RevocationPredicateToken(PabcSerializer.RevocationPredicateToken revocationPredToken) {
        this.V_RA      = new Group1ElementBLS461(revocationPredToken.getVRA());
        this.V_issuer  = new Group1ElementBLS461(revocationPredToken.getVIssuer());
        this.proof     = new PSzkTokenModified(revocationPredToken.getProof());
        this.S_open_RA = new ZpElementBLS461(revocationPredToken.getSOpenRA());
        this.S_open_issuer = new ZpElementBLS461(revocationPredToken.getSOpenIssuer());
        this.S_rh = new ZpElementBLS461(revocationPredToken.getSRh());
        this.c = new ZpElementBLS461(revocationPredToken.getC());
        this.revocationEpoch = revocationPredToken.getRevocationEpoch();
    }

    public long getEpoch() {
    	return revocationEpoch;
    }
    
    public Group1Element getV_RA() {
		return V_RA;
	}
    
    public Group1Element getV_issuer() {
		return V_issuer;
	}

	public MSzkToken getProof() {
		return proof;
	}
	
	public ZpElement getS_open_RA() {
		return S_open_RA;
	}

	public ZpElement getS_open_issuer() {
		return S_open_issuer;
	}

	public ZpElement getS_rh() {
		return S_rh;
	}

	public ZpElement getC() {
		return c;
	}

    public PabcSerializer.RevocationPredicateToken toProto() {
        return PabcSerializer.RevocationPredicateToken.newBuilder()
				.setVRA(V_RA.toProto())
				.setVIssuer(V_issuer.toProto())
				.setProof(((PSzkTokenModified)proof).toProto())
				.setSOpenRA(S_open_RA.toProto())
				.setSOpenIssuer(S_open_issuer.toProto())
				.setSRh(S_rh.toProto())
				.setC(c.toProto())
                .setRevocationEpoch(revocationEpoch)
                .build();
    }
}
