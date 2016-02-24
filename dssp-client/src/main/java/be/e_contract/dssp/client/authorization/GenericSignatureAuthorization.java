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

import java.util.LinkedList;
import java.util.List;
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
 * Generic implementation of a signature authorization policy provider.
 *
 * @author Frank Cornelis
 *
 */
public class GenericSignatureAuthorization implements SignatureAuthorization {

	private final List<String> authorizedSubjectNames;

	private final List<String> authorizedSubjectRegexps;

	private final List<String> authorizedCardNumbers;

	private final List<String> nonAuthorizedSubjectNames;

	private final List<String> nonAuthorizedSubjectRegexps;

	private final List<String> nonAuthorizedCardNumbers;

	private final ObjectFactory xacmlObjectFactory;

	/**
	 * Main constructor.
	 */
	public GenericSignatureAuthorization() {
		this.authorizedSubjectNames = new LinkedList<String>();
		this.authorizedSubjectRegexps = new LinkedList<String>();
		this.authorizedCardNumbers = new LinkedList<String>();
		this.nonAuthorizedSubjectNames = new LinkedList<String>();
		this.nonAuthorizedSubjectRegexps = new LinkedList<String>();
		this.nonAuthorizedCardNumbers = new LinkedList<String>();

		this.xacmlObjectFactory = new ObjectFactory();
	}

	/**
	 * Adds an authorized subject name. This is the certificate DN.
	 *
	 * @param subjectName
	 *            the X500 subject name.
	 */
	public void addAuthorizedSubjectName(String subjectName) {
		this.authorizedSubjectNames.add(subjectName);
	}

	/**
	 * Adds an authorized subject as regular expression.
	 *
	 * @param regexp
	 */
	public void addAuthorizedSubjectRegexp(String regexp) {
		this.authorizedSubjectRegexps.add(regexp);
	}

	/**
	 * Adds an authorized eID card number.
	 *
	 * @param cardNumber
	 */
	public void addAuthorizedCardNumber(String cardNumber) {
		this.authorizedCardNumbers.add(cardNumber);
	}

	/**
	 * Add a subject name that is not authorized to sign. This is the
	 * certificate DN.
	 *
	 * @param subjectName
	 *            the X500 subject name.
	 */
	public void addNonAuthorizedSubjectName(String subjectName) {
		this.nonAuthorizedSubjectNames.add(subjectName);
	}

	/**
	 * Adds a subject name regular expression that is not authorized to sign.
	 *
	 * @param regexp
	 */
	public void addNonAuthorizedSubjectRegexp(String regexp) {
		this.nonAuthorizedSubjectRegexps.add(regexp);
	}

	/**
	 * Adds an eID card number that is not authorized to sign.
	 *
	 * @param cardNumber
	 */
	public void addNonAuthorizedCardNumber(String cardNumber) {
		this.nonAuthorizedCardNumbers.add(cardNumber);
	}

	private SubjectType createSubject(String matchId, String attributeDataType, String attributeValue,
			String attributeId, String attributeDesignatorDataType) {
		SubjectType subject = this.xacmlObjectFactory.createSubjectType();
		SubjectMatchType subjectMatch = this.xacmlObjectFactory.createSubjectMatchType();
		subject.getSubjectMatch().add(subjectMatch);
		subjectMatch.setMatchId(matchId);
		AttributeValueType subjectAttributeValue = this.xacmlObjectFactory.createAttributeValueType();
		subjectMatch.setAttributeValue(subjectAttributeValue);
		subjectAttributeValue.setDataType(attributeDataType);
		subjectAttributeValue.getContent().add(attributeValue);
		SubjectAttributeDesignatorType subjectAttributeDesignator = this.xacmlObjectFactory
				.createSubjectAttributeDesignatorType();
		subjectMatch.setSubjectAttributeDesignator(subjectAttributeDesignator);
		subjectAttributeDesignator.setAttributeId(attributeId);
		subjectAttributeDesignator.setDataType(attributeDesignatorDataType);
		return subject;
	}

	@Override
	public PolicyType getXACMLPolicy() {
		PolicyType policy = this.xacmlObjectFactory.createPolicyType();
		policy.setPolicyId("urn:" + UUID.randomUUID().toString());
		policy.setRuleCombiningAlgId("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides");

		TargetType target = this.xacmlObjectFactory.createTargetType();
		policy.setTarget(target);

		ResourcesType resources = this.xacmlObjectFactory.createResourcesType();
		target.setResources(resources);
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
		target.setActions(actions);
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

		RuleType permitRule = this.xacmlObjectFactory.createRuleType();
		policy.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().add(permitRule);
		permitRule.setRuleId("permit-subject");
		permitRule.setEffect(EffectType.PERMIT);

		if (!this.authorizedCardNumbers.isEmpty() || !this.authorizedSubjectNames.isEmpty()
				|| !this.authorizedSubjectRegexps.isEmpty()) {
			TargetType permitRuleTarget = this.xacmlObjectFactory.createTargetType();
			permitRule.setTarget(permitRuleTarget);
			SubjectsType subjects = this.xacmlObjectFactory.createSubjectsType();
			permitRuleTarget.setSubjects(subjects);
			for (String authorizedSubjectName : this.authorizedSubjectNames) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:1.0:function:x500Name-equal",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name", authorizedSubjectName,
						"urn:oasis:names:tc:xacml:1.0:subject:subject-id",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name");
				subjects.getSubject().add(subject);
			}
			for (String authorizedSubjectRegexp : this.authorizedSubjectRegexps) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:2.0:function:x500Name-regexp-match",
						"http://www.w3.org/2001/XMLSchema#string", authorizedSubjectRegexp,
						"urn:oasis:names:tc:xacml:1.0:subject:subject-id",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name");
				subjects.getSubject().add(subject);
			}
			for (String authorizedCardNumber : this.authorizedCardNumbers) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:1.0:function:string-equal",
						"http://www.w3.org/2001/XMLSchema#string", authorizedCardNumber,
						"urn:be:e-contract:dss:eid:card-number", "http://www.w3.org/2001/XMLSchema#string");
				subjects.getSubject().add(subject);
			}
		}

		if (!this.nonAuthorizedCardNumbers.isEmpty() || !this.nonAuthorizedSubjectNames.isEmpty()
				|| !this.nonAuthorizedSubjectRegexps.isEmpty()) {
			RuleType denyRule = this.xacmlObjectFactory.createRuleType();
			policy.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().add(denyRule);
			denyRule.setRuleId("deny-subject");
			denyRule.setEffect(EffectType.DENY);

			TargetType denyRuleTarget = this.xacmlObjectFactory.createTargetType();
			denyRule.setTarget(denyRuleTarget);
			SubjectsType subjects = this.xacmlObjectFactory.createSubjectsType();
			denyRuleTarget.setSubjects(subjects);
			for (String nonAuthorizedSubjectName : this.nonAuthorizedSubjectNames) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:1.0:function:x500Name-equal",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name", nonAuthorizedSubjectName,
						"urn:oasis:names:tc:xacml:1.0:subject:subject-id",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name");
				subjects.getSubject().add(subject);
			}
			for (String nonAuthorizedSubjectRegexp : this.nonAuthorizedSubjectRegexps) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:2.0:function:x500Name-regexp-match",
						"http://www.w3.org/2001/XMLSchema#string", nonAuthorizedSubjectRegexp,
						"urn:oasis:names:tc:xacml:1.0:subject:subject-id",
						"urn:oasis:names:tc:xacml:1.0:data-type:x500Name");
				subjects.getSubject().add(subject);
			}
			for (String nonAuthorizedCardNumber : this.nonAuthorizedCardNumbers) {
				SubjectType subject = createSubject("urn:oasis:names:tc:xacml:1.0:function:string-equal",
						"http://www.w3.org/2001/XMLSchema#string", nonAuthorizedCardNumber,
						"urn:be:e-contract:dss:eid:card-number", "http://www.w3.org/2001/XMLSchema#string");
				subjects.getSubject().add(subject);
			}
		}

		return policy;
	}
}