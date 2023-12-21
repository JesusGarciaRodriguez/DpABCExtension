package eu.olympus.model;

import java.util.Set;

import eu.olympus.util.inspection.model.ElGamalKey;

public class PabcPublicParameters {

    private Set<AttributeDefinition> attributeDefinitions;
    private String encodedSchemePublicParam;
    private String encodedInspectionKey;
    private String encodedRevocationKey;

    public PabcPublicParameters() {
    }

    public PabcPublicParameters(Set<AttributeDefinition> attributeDefinitions, String encodedSchemePublicParam) {
        this.attributeDefinitions = attributeDefinitions;
        this.encodedSchemePublicParam = encodedSchemePublicParam;
    }

    public PabcPublicParameters(Set<AttributeDefinition> attributeDefinitions, String encodedSchemePublicParam, String encodedInspectionKey, String encodedRevocationKey) {
        this.attributeDefinitions = attributeDefinitions;
        this.encodedSchemePublicParam = encodedSchemePublicParam;
        this.encodedInspectionKey = encodedInspectionKey;
        this.encodedRevocationKey = encodedRevocationKey;
    }

    public Set<AttributeDefinition> getAttributeDefinitions() {
        return attributeDefinitions;
    }

    public void setAttributeDefinitions(Set<AttributeDefinition> attributeDefinitions) {
        this.attributeDefinitions = attributeDefinitions;
    }

    public String getEncodedSchemePublicParam() {
        return encodedSchemePublicParam;
    }

    public void setEncodedSchemePublicParam(String encodedSchemePublicParam) {
        this.encodedSchemePublicParam = encodedSchemePublicParam;
    }

    public String getEncodedInspectionKey() {
        return encodedInspectionKey;
    }

    public void setEncodedInspectionKey(String encodedInspectionKey) {
        this.encodedInspectionKey = encodedInspectionKey;
    }

    public String getEncodedRevocationKey() {
        return encodedRevocationKey;
    }

    public void setEncodedRevocationKey(String encodedRevocationKey) {
        this.encodedRevocationKey = encodedRevocationKey;
    }
}
