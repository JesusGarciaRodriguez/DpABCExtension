package eu.olympus.model;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.inspection.InspectionPredicateToken;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pseudonym.PseudonymPredicateToken;
import eu.olympus.util.psmultisign.PSzkToken;
import eu.olympus.util.psmultisign.PSzkTokenModified;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.revocation.RevocationPredicateToken;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PresentationToken {

	private final long epoch;
	private final Map<String, Attribute> revealedAttributes;
	private final Map<String, RangePredicateToken> rangeTokens;
	private final MSzkToken zkToken;
	private final InspectionPredicateToken inspectionToken;
	private final RevocationPredicateToken revocationToken;

	private final PseudonymPredicateToken pseudonymToken;

	public PresentationToken(long epoch, Map<String, Attribute> revealedAttributes, MSzkToken zkToken,  Map<String, RangePredicateToken> rangeTokens, InspectionPredicateToken inspectionToken, RevocationPredicateToken revocationToken, PseudonymPredicateToken pseudonymToken) {
		this.epoch = epoch;
		this.revealedAttributes = revealedAttributes;
		this.rangeTokens = rangeTokens==null ? new HashMap<>() : new HashMap<>(rangeTokens);
		this.zkToken = zkToken;
		this.inspectionToken = inspectionToken;
		this.revocationToken = revocationToken;
		this.pseudonymToken = pseudonymToken;
	}

	public PresentationToken(String presentationToken) throws InvalidProtocolBufferException {
		PabcSerializer.PresentationToken protoPT = PabcSerializer.PresentationToken
				.parseFrom(Base64.decodeBase64(presentationToken));
		this.inspectionToken = protoPT.hasInspectionPredicate()? new InspectionPredicateToken(protoPT.getInspectionPredicate()):null;
		this.revocationToken = protoPT.hasRevocationToken()? new RevocationPredicateToken(protoPT.getRevocationToken()):null;
		this.pseudonymToken = protoPT.hasPseudonymToken()? new PseudonymPredicateToken(protoPT.getPseudonymToken()):null;
		this.epoch = protoPT.getEpoch();
		this.revealedAttributes = new HashMap<>();
		Map<String, PabcSerializer.Attribute> protoAttr = protoPT.getRevealedAttributesMap();
		for (String attrName : protoAttr.keySet()) {
			revealedAttributes.put(attrName, new Attribute(protoAttr.get(attrName)));
		}
		if(protoPT.hasPsZkToken()){
			zkToken = new PSzkToken(protoPT.getPsZkToken());
		}else {
			zkToken = new PSzkTokenModified(protoPT.getPsZkTokenMod());
		}
		this.rangeTokens = new HashMap<>();
		Map<String, PabcSerializer.RangePredToken> protoTokens= protoPT.getRangePredTokensMap();
		for(String attrName: protoTokens.keySet())
			rangeTokens.put(attrName,new RangePredicateToken(protoTokens.get(attrName)));
	}

	public long getEpoch() {
		return epoch;
	}

	public Map<String, Attribute> getRevealedAttributes() {
		return revealedAttributes;
	}

	public MSzkToken getZkToken() {
		return zkToken;
	}

	public String getEncoded() {
		return Base64.encodeBase64String(toProto().toByteArray());
	}

	public Map<String, RangePredicateToken> getRangeTokens() {
		return rangeTokens;
	}

	public InspectionPredicateToken getInspectionToken() {
		return inspectionToken;
	}

	public RevocationPredicateToken getRevocationToken() {
		return revocationToken;
	}

	public PseudonymPredicateToken getPseudonymToken() {
		return pseudonymToken;
	}

	private PabcSerializer.PresentationToken toProto() {
		Map<String, PabcSerializer.Attribute> protoAttributes = new HashMap<>();
		for (String attrName : revealedAttributes.keySet())
			protoAttributes.put(attrName, revealedAttributes.get(attrName).toProto());
		Map<String, PabcSerializer.RangePredToken> protoTokens= new HashMap<>();
		for(String attrName:rangeTokens.keySet()){
			protoTokens.put(attrName,rangeTokens.get(attrName).toProto());
		}
		PabcSerializer.PresentationToken.Builder token=PabcSerializer.PresentationToken.newBuilder()
				.setEpoch(epoch).putAllRevealedAttributes(protoAttributes).putAllRangePredTokens(protoTokens);
		if(inspectionToken!=null)
			token.setInspectionPredicate(inspectionToken.toProto());
		if(revocationToken!=null)
			token.setRevocationToken(revocationToken.toProto());
		if(pseudonymToken!=null)
			token.setPseudonymToken(pseudonymToken.toProto());
		if (zkToken instanceof PSzkToken)
			return token.setPsZkToken(((PSzkToken) zkToken).toProto()).build();
		else
			return token.setPsZkTokenMod(((PSzkTokenModified) zkToken).toProto()).build();
	}

}
