package eu.olympus.model;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Policy {

	private List<Predicate> predicates;
	private String policyId;

    public Policy(List<Predicate> predicates, String policyId) {
		super();
		this.predicates = predicates;
		this.policyId = policyId;
	}

	public Policy() {
    }

	public List<Predicate> getPredicates() {
		return predicates;
	}

	public void setPredicates(List<Predicate> predicates) {
		this.predicates = predicates;
	}

	public String getPolicyId() {
		return policyId;
	}

	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}

	public String generateZkContext(){
		StringBuilder builder=new StringBuilder();
		//Add freshness and base presentation proof goal
		builder.append(policyId).append("-");
		String revealGoals=predicates.stream().filter(p->p.getOperation()==Operation.REVEAL).sorted(Comparator.comparing(Predicate::getAttributeName)).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
		if (!revealGoals.isEmpty())
			builder.append(revealGoals).append(";");
		String equalGoals=predicates.stream().filter(p->p.getOperation()==Operation.EQ).sorted(Comparator.comparing(Predicate::getAttributeName).thenComparing(p -> p.getValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
		if (!equalGoals.isEmpty())
			builder.append(equalGoals).append(";");
		//Parse subproof goals ordered according to attribute they apply to
		List<String> orderedAttributes=predicates.stream().filter(p->p.getOperation()!=Operation.REVEAL && p.getOperation()!=Operation.EQ).map(Predicate::getAttributeName).sorted().distinct().collect(Collectors.toList());
		for(String attr:orderedAttributes){
			builder.append("-:").append(attr).append(":-");
			List<Predicate> preds=predicates.stream().filter(p->p.getAttributeName().equals(attr)).collect(Collectors.toList());
 			//First pseudonym predicates
			String pseudonymGoals=preds.stream().filter(p->p.getOperation()==Operation.PSEUDONYM).sorted(Comparator.comparing(p -> p.getValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!pseudonymGoals.isEmpty())
				builder.append(pseudonymGoals).append(";");
			//Second inspection predicates
			String inspectionGoals=preds.stream().filter(p->p.getOperation()==Operation.INSPECTION).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!inspectionGoals.isEmpty())
				builder.append(inspectionGoals).append(";");
			//Third revocation predicates
			String revocationGoals=preds.stream().filter(p->p.getOperation()==Operation.REVOCATION).sorted(Comparator.comparing(p -> p.getValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!revocationGoals.isEmpty())
				builder.append(revocationGoals).append(";");
			//Fourth range predicates
			String leGoals=preds.stream().filter(p->p.getOperation()==Operation.LESSTHANOREQUAL).sorted(Comparator.comparing(p -> p.getValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!leGoals.isEmpty())
				builder.append(leGoals).append(";");
			String geGoals=preds.stream().filter(p->p.getOperation()==Operation.GREATERTHANOREQUAL).sorted(Comparator.comparing(p -> p.getValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!geGoals.isEmpty())
				builder.append(geGoals).append(";");
			String rangeGoals=preds.stream().filter(p->p.getOperation()==Operation.INRANGE).sorted(Comparator.comparing((Predicate p) -> p.getValue().getAttr().toString()).thenComparing((Predicate p) -> p.getExtraValue().getAttr().toString())).map(Predicate::serialProofGoal).distinct().collect(Collectors.joining(","));
			if (!rangeGoals.isEmpty())
				builder.append(rangeGoals).append(";");
		}
		return builder.toString();
	}

}
