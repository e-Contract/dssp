/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2016 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

package be.e_contract.dssp.client.authorization;

import java.util.Set;
import java.util.UUID;

import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionMatchType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionsType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.AttributeDesignatorType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.AttributeValueType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.EffectType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.xacml.policy.PolicyType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ResourceMatchType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ResourceType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ResourcesType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.RuleType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.SubjectAttributeDesignatorType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.SubjectMatchType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.SubjectType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.SubjectsType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.TargetType;

/**
 * Signature authorization based on subjects. An authorized subject can be an
 * regular expression.
 *
 * @author Frank Cornelis
 *
 */
public class AuthorizedCardNumbersSignatureAuthorization implements SignatureAuthorization {

	private final Set<String> authorizedCardNumbers;

	private final ObjectFactory xacmlObjectFactory;

	/**
	 * Main constructor.
	 *
	 * @param authorizedCardNumbers
	 *            the signatory eID card numbers that are authorized to sign.
	 */
	public AuthorizedCardNumbersSignatureAuthorization(Set<String> authorizedCardNumbers) {
		this.authorizedCardNumbers = authorizedCardNumbers;
		this.xacmlObjectFactory = new ObjectFactory();
	}

	@Override
	public PolicyType getXACMLPolicy() {
		PolicyType policy = this.xacmlObjectFactory.createPolicyType();
		policy.setPolicyId("urn:" + UUID.randomUUID().toString());
		policy.setRuleCombiningAlgId("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides");
		TargetType target = this.xacmlObjectFactory.createTargetType();
		policy.setTarget(target);
		RuleType rule = this.xacmlObjectFactory.createRuleType();
		policy.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().add(rule);
		rule.setRuleId("whatever");
		rule.setEffect(EffectType.PERMIT);
		TargetType ruleTarget = this.xacmlObjectFactory.createTargetType();
		rule.setTarget(ruleTarget);
		SubjectsType subjects = this.xacmlObjectFactory.createSubjectsType();
		ruleTarget.setSubjects(subjects);
		for (String authorizedSubject : this.authorizedCardNumbers) {
			SubjectType subject = this.xacmlObjectFactory.createSubjectType();
			subjects.getSubject().add(subject);
			SubjectMatchType subjectMatch = this.xacmlObjectFactory.createSubjectMatchType();
			subject.getSubjectMatch().add(subjectMatch);
			subjectMatch.setMatchId("urn:oasis:names:tc:xacml:1.0:function:string-equal");
			AttributeValueType attributeValue = this.xacmlObjectFactory.createAttributeValueType();
			subjectMatch.setAttributeValue(attributeValue);
			attributeValue.setDataType("http://www.w3.org/2001/XMLSchema#string");
			attributeValue.getContent().add(authorizedSubject);
			SubjectAttributeDesignatorType subjectAttributeDesigator = this.xacmlObjectFactory
					.createSubjectAttributeDesignatorType();
			subjectMatch.setSubjectAttributeDesignator(subjectAttributeDesigator);
			subjectAttributeDesigator.setAttributeId("urn:be:e-contract:dss:eid:card-number");
			subjectAttributeDesigator.setDataType("http://www.w3.org/2001/XMLSchema#string");
		}
		ResourcesType resources = this.xacmlObjectFactory.createResourcesType();
		ruleTarget.setResources(resources);
		ResourceType resource = this.xacmlObjectFactory.createResourceType();
		resources.getResource().add(resource);
		ResourceMatchType resourceMatch = this.xacmlObjectFactory.createResourceMatchType();
		resource.getResourceMatch().add(resourceMatch);
		resourceMatch.setMatchId("urn:oasis:names:tc:xacml:1.0:function:anyURI-equal");
		AttributeValueType resourceAttributeValue = this.xacmlObjectFactory.createAttributeValueType();
		resourceMatch.setAttributeValue(resourceAttributeValue);
		resourceAttributeValue.setDataType("http://www.w3.org/2001/XMLSchema#anyURI");
		resourceAttributeValue.getContent().add("urn:be:e-contract:dss");
		AttributeDesignatorType resourceAttributeDesignator = this.xacmlObjectFactory.createAttributeDesignatorType();
		resourceMatch.setResourceAttributeDesignator(resourceAttributeDesignator);
		resourceAttributeDesignator.setAttributeId("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
		resourceAttributeDesignator.setDataType("http://www.w3.org/2001/XMLSchema#anyURI");

		ActionsType actions = this.xacmlObjectFactory.createActionsType();
		ruleTarget.setActions(actions);
		ActionType action = this.xacmlObjectFactory.createActionType();
		actions.getAction().add(action);
		ActionMatchType actionMatch = this.xacmlObjectFactory.createActionMatchType();
		action.getActionMatch().add(actionMatch);
		actionMatch.setMatchId("urn:oasis:names:tc:xacml:1.0:function:string-equal");
		AttributeValueType actionAttributeValue = this.xacmlObjectFactory.createAttributeValueType();
		actionMatch.setAttributeValue(actionAttributeValue);
		actionAttributeValue.setDataType("http://www.w3.org/2001/XMLSchema#string");
		actionAttributeValue.getContent().add("sign");
		AttributeDesignatorType actionAttributeDesignator = this.xacmlObjectFactory.createAttributeDesignatorType();
		actionMatch.setActionAttributeDesignator(actionAttributeDesignator);
		actionAttributeDesignator.setAttributeId("urn:oasis:names:tc:xacml:1.0:action:action-id");
		actionAttributeDesignator.setDataType("http://www.w3.org/2001/XMLSchema#string");

		return policy;
	}
}
