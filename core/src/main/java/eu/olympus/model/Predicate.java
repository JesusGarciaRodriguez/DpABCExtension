package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Predicate {

	private String attributeName;
	private Operation operation;
	private Attribute value;
	private Attribute extraValue; //Needed for new "In range" predicate. There may be a better way to do this (for other possible operations too)
	
	public Predicate() {
	}

	public Predicate(String attributeName, Operation operation) {
		this.attributeName = attributeName;
		this.operation = operation;
	}
	
	public Predicate(String attributeName, Operation operation, Attribute value) {
		this.attributeName = attributeName;
		this.operation = operation;
		this.value = value;
	}

	public Predicate(String attributeName, Operation operation, Attribute value,Attribute extraValue) {
		this.attributeName = attributeName;
		this.operation = operation;
		this.value = value;
		this.extraValue=extraValue;
	}

	public String getAttributeName() {
		return attributeName;
	}

	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
	}
	
	public Operation getOperation() {
		return operation;
	}
	
	public void setOperation(Operation operation) {
		this.operation = operation;
	}
	
	public Attribute getValue() {
		return value;
	}
	
	public void setValue(Attribute value) {
		this.value = value;
	}

	public Attribute getExtraValue() {
		return extraValue;
	}

	public void setExtraValue(Attribute extraValue) {
		this.extraValue = extraValue;
	}

	public String serialProofGoal(){
		StringBuilder builder=new StringBuilder();
		builder.append(operation).append("_");
		switch (operation){
			case LESSTHANOREQUAL:
			case REVOCATION:
			case PSEUDONYM:
			case GREATERTHANOREQUAL:
				builder.append(value.toString());
				break;
			case EQ:
				builder.append(attributeName).append("_").append(value.toString());
				break;
			case REVEAL:
				builder.append(attributeName);
				break;
			case INRANGE:
				builder.append(value.toString()).append(extraValue.toString());
				break;
			case INSPECTION:
				builder.setLength(builder.length() - 1);
				break;
		}
		return builder.toString();
	}
}
