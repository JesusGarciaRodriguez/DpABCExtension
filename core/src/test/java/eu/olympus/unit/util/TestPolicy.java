package eu.olympus.unit.util;

import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.util.Util;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ROM;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class TestPolicy {

    @Test
    public void testGenerateZkContext() {
        String expectedValue="FreshnessId-REVEAL_b_attribute,REVEAL_k_attribute,REVEAL_l_attribute;EQ_c_attribute_24;-:a_attribute:-PSEUDONYM_scope:a,PSEUDONYM_scope:b;INSPECTION_inspector;-:e_attribute:-INRANGE_1020;-:f_attribute:-LESSTHANOREQUAL_26,LESSTHANOREQUAL_45;";
        List<Predicate> predicates=new LinkedList<>();
        predicates.add(new Predicate("a_attribute", Operation.INSPECTION));
        predicates.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:a")));
        predicates.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:b")));
        predicates.add(new Predicate("b_attribute", Operation.REVEAL));
        predicates.add(new Predicate("c_attribute", Operation.EQ,new Attribute(24)));
        predicates.add(new Predicate("e_attribute", Operation.INRANGE,new Attribute(10),new Attribute(20)));
        predicates.add(new Predicate("f_attribute", Operation.LESSTHANOREQUAL,new Attribute(26)));
        predicates.add(new Predicate("f_attribute", Operation.LESSTHANOREQUAL,new Attribute(45)));
        predicates.add(new Predicate("k_attribute", Operation.REVEAL));
        predicates.add(new Predicate("l_attribute", Operation.REVEAL));
        Policy policy= new Policy(predicates,"FreshnessId");
        assertEquals(expectedValue,policy.generateZkContext());
        List<Predicate> predicates2=new LinkedList<>();
        predicates2.add(new Predicate("k_attribute", Operation.REVEAL));
        predicates2.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:a")));
        predicates2.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:b")));
        predicates2.add(new Predicate("f_attribute", Operation.LESSTHANOREQUAL,new Attribute(45)));
        predicates2.add(new Predicate("c_attribute", Operation.EQ,new Attribute(24)));
        predicates2.add(new Predicate("a_attribute", Operation.INSPECTION));
        predicates2.add(new Predicate("e_attribute", Operation.INRANGE,new Attribute(10),new Attribute(20)));
        predicates2.add(new Predicate("f_attribute", Operation.LESSTHANOREQUAL,new Attribute(26)));
        predicates2.add(new Predicate("b_attribute", Operation.REVEAL));
        predicates2.add(new Predicate("l_attribute", Operation.REVEAL));
        Policy policy2= new Policy(predicates2,"FreshnessId");
        assertEquals(expectedValue,policy2.generateZkContext());
        List<Predicate> predicates3=new LinkedList<>();
        predicates3.add(new Predicate("k_attribute", Operation.REVEAL));
        predicates3.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:d")));
        predicates3.add(new Predicate("a_attribute", Operation.PSEUDONYM,new Attribute("scope:b")));
        predicates3.add(new Predicate("f_attribute", Operation.LESSTHANOREQUAL,new Attribute(45)));
        predicates3.add(new Predicate("c_attribute", Operation.EQ,new Attribute(24)));
        predicates3.add(new Predicate("a_attribute", Operation.INSPECTION));
        predicates3.add(new Predicate("e_attribute", Operation.INRANGE,new Attribute(10),new Attribute(20)));
        predicates3.add(new Predicate("b_attribute", Operation.REVEAL));
        predicates3.add(new Predicate("l_attribute", Operation.REVEAL));
        Policy policy3= new Policy(predicates3,"FreshnessId");
        String expectedValue3="FreshnessId-REVEAL_b_attribute,REVEAL_k_attribute,REVEAL_l_attribute;EQ_c_attribute_24;-:a_attribute:-PSEUDONYM_scope:b,PSEUDONYM_scope:d;INSPECTION_inspector;-:e_attribute:-INRANGE_1020;-:f_attribute:-LESSTHANOREQUAL_45;";
        assertEquals(expectedValue3,policy3.generateZkContext());

    }
}
