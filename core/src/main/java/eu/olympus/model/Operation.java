package eu.olympus.model;

public enum Operation {
	LESSTHANOREQUAL, // <= predicate, expected: value: boundary (integer), extraValue: null
	EQ, // == predicate, expected: value: expected value (integer), extraValue: null
	GREATERTHANOREQUAL,  // >= predicate, expected: value: boundary (integer), extraValue: null
	REVEAL, // reveal the attribute, expected: value: null, extraValue: null
	INRANGE, // a<=b<=c predicate, expected: value: lower bound (integer), extraValue: upper bound
	INSPECTION, // inspection predicate, expected: value: null, extraValue: null //TODO Might be interesting to add inspection key here in the future?
	REVOCATION, // revocation predicate, expected: value: <lowest> allowed epoch (integer), extraValue: null
	PSEUDONYM // pseudonym predicate, expected: value: scope (string), extraValue: null
}
