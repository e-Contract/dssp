/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2014 e-Contract.be BVBA.
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

package be.e_contract.dssp.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.jaxb.dss.AnyType;
import be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.dss.async.PendingRequest;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemNameEnum;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemValueStringType;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemValueURIType;
import be.e_contract.dssp.ws.jaxb.dss.vs.PixelVisibleSignaturePositionType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureConfigurationType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureItemType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureItemsConfigurationType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignaturePolicyType;
import be.e_contract.dssp.ws.jaxb.wsa.AttributedURIType;
import be.e_contract.dssp.ws.jaxb.wsa.EndpointReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.ReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.SecurityTokenReferenceType;
import be.e_contract.dssp.ws.jaxb.wsu.AttributedDateTime;
import be.e_contract.dssp.ws.jaxb.wsu.TimestampType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionMatchType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ActionsType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.AttributeDesignatorType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.AttributeValueType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.EffectType;
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
 * Factory for dss:PendingRequest. To be used during the Browser POST.
 * 
 * @author Frank Cornelis
 * 
 */
public class PendingRequestFactory {

	private PendingRequestFactory() {
		super();
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 * 
	 * @param session
	 *            the session object.
	 * @param destination
	 *            the destination URL within your web application. This is where
	 *            the DSS will return to.
	 * @param language
	 *            the optional language
	 * @return
	 */
	public static String createPendingRequest(
			DigitalSignatureServiceSession session, String destination,
			String language) {
		return createPendingRequest(session, destination, language, null);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 * 
	 * @param session
	 *            the session object.
	 * @param destination
	 *            the destination URL within your web application. This is where
	 *            the DSS will return to.
	 * @param language
	 *            the optional language
	 * @param visibleSignatureConfiguration
	 *            the optional visible signature configuration.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(
			DigitalSignatureServiceSession session, String destination,
			String language,
			VisibleSignatureConfiguration visibleSignatureConfiguration) {
		return createPendingRequest(session, destination, language,
				visibleSignatureConfiguration, false, null);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 * 
	 * <p>
	 * The content of the parameter {@code authorizedSubjects} can be
	 * constructed as follows. The {@code authorizedSubjects} parameter is a set
	 * of regular expressions. Suppose you have a national registration number
	 * that is allowed to sign, then you can construct the
	 * {@code authorizedSubjects} as follows.
	 * </p>
	 * 
	 * <pre>
	 * Set&lt;String&gt; authorizedSubjects = new HashSet&lt;String&gt;();
	 * String nrn = &quot;1234&quot;;
	 * X500Principal x500Principal = new X500Principal(&quot;SERIALNUMBER=&quot; + nrn);
	 * String authorizedSubject = x500Principal.getName() + &quot;,.*,C=BE&quot;;
	 * authorizedSubjects.add(authorizedSubject);
	 * </pre>
	 * 
	 * @param session
	 *            the session object.
	 * @param destination
	 *            the destination URL within your web application. This is where
	 *            the DSS will return to.
	 * @param language
	 *            the optional language
	 * @param visibleSignatureConfiguration
	 *            the optional visible signature configuration.
	 * @param returnSignerIdentity
	 *            indicates whether the DSS should return the signatory's
	 *            identity.
	 * @param authorizedSubjects
	 *            the optional signatory subject DNs that are authorized to
	 *            sign. An authorized subject can be an regular expression.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(
			DigitalSignatureServiceSession session, String destination,
			String language,
			VisibleSignatureConfiguration visibleSignatureConfiguration,
			boolean returnSignerIdentity, Set<String> authorizedSubjects) {
		ObjectFactory asyncObjectFactory = new ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dss.ObjectFactory dssObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory wsaObjectFactory = new be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory wsuObjectFactory = new be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory vsObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory xacmlObjectFactory = new be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory();

		PendingRequest pendingRequest = asyncObjectFactory
				.createPendingRequest();
		pendingRequest.setProfile(DigitalSignatureServiceConstants.PROFILE);
		AnyType optionalInputs = dssObjectFactory.createAnyType();
		pendingRequest.setOptionalInputs(optionalInputs);

		optionalInputs
				.getAny()
				.add(dssObjectFactory
						.createAdditionalProfile(DigitalSignatureServiceConstants.DSS_ASYNC_PROFILE));
		optionalInputs.getAny().add(
				asyncObjectFactory.createResponseID(session.getResponseId()));

		if (null != language) {
			optionalInputs.getAny().add(
					dssObjectFactory.createLanguage(language));
		}

		if (returnSignerIdentity) {
			optionalInputs.getAny().add(
					dssObjectFactory.createReturnSignerIdentity(null));
		}

		AttributedURIType messageId = wsaObjectFactory
				.createAttributedURIType();
		optionalInputs.getAny()
				.add(wsaObjectFactory.createMessageID(messageId));
		String requestId = "uuid:" + UUID.randomUUID().toString();
		messageId.setValue(requestId);
		session.setInResponseTo(requestId);

		TimestampType timestamp = wsuObjectFactory.createTimestampType();
		optionalInputs.getAny()
				.add(wsuObjectFactory.createTimestamp(timestamp));
		AttributedDateTime created = wsuObjectFactory
				.createAttributedDateTime();
		timestamp.setCreated(created);
		DateTimeFormatter dateTimeFormatter = ISODateTimeFormat.dateTime()
				.withChronology(ISOChronology.getInstanceUTC());
		DateTime createdDateTime = new DateTime();
		created.setValue(dateTimeFormatter.print(createdDateTime));
		AttributedDateTime expires = wsuObjectFactory
				.createAttributedDateTime();
		timestamp.setExpires(expires);
		DateTime expiresDateTime = createdDateTime.plusMinutes(5);
		expires.setValue(dateTimeFormatter.print(expiresDateTime));

		EndpointReferenceType replyTo = wsaObjectFactory
				.createEndpointReferenceType();
		optionalInputs.getAny().add(wsaObjectFactory.createReplyTo(replyTo));
		AttributedURIType address = wsaObjectFactory.createAttributedURIType();
		replyTo.setAddress(address);
		address.setValue(destination);
		session.setDestination(destination);

		if (null != visibleSignatureConfiguration) {
			VisibleSignatureConfigurationType visSigConfig = vsObjectFactory
					.createVisibleSignatureConfigurationType();
			optionalInputs.getAny().add(
					vsObjectFactory
							.createVisibleSignatureConfiguration(visSigConfig));
			VisibleSignaturePolicyType visibleSignaturePolicy = VisibleSignaturePolicyType.DOCUMENT_SUBMISSION_POLICY;
			visSigConfig.setVisibleSignaturePolicy(visibleSignaturePolicy);
			VisibleSignatureItemsConfigurationType visibleSignatureItemsConfiguration = vsObjectFactory
					.createVisibleSignatureItemsConfigurationType();
			visSigConfig
					.setVisibleSignatureItemsConfiguration(visibleSignatureItemsConfiguration);
			if (visibleSignatureConfiguration.getLocation() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem()
						.add(locationVisibleSignatureItem);
				locationVisibleSignatureItem
						.setItemName(ItemNameEnum.SIGNATURE_PRODUCTION_PLACE);
				ItemValueStringType itemValue = vsObjectFactory
						.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration
						.getLocation());
			}
			if (visibleSignatureConfiguration.getRole() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem()
						.add(locationVisibleSignatureItem);
				locationVisibleSignatureItem
						.setItemName(ItemNameEnum.SIGNATURE_REASON);
				ItemValueStringType itemValue = vsObjectFactory
						.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getRole());
			}
			if (visibleSignatureConfiguration.getProfile() != null) {
				PixelVisibleSignaturePositionType visibleSignaturePosition = vsObjectFactory
						.createPixelVisibleSignaturePositionType();
				visSigConfig
						.setVisibleSignaturePosition(visibleSignaturePosition);
				visibleSignaturePosition.setPageNumber(BigInteger
						.valueOf(visibleSignatureConfiguration.getPage()));
				visibleSignaturePosition.setX(BigInteger
						.valueOf(visibleSignatureConfiguration.getX()));
				visibleSignaturePosition.setY(BigInteger
						.valueOf(visibleSignatureConfiguration.getY()));

				VisibleSignatureItemType visibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem()
						.add(visibleSignatureItem);
				visibleSignatureItem.setItemName(ItemNameEnum.SIGNER_IMAGE);
				ItemValueURIType itemValue = vsObjectFactory
						.createItemValueURIType();
				itemValue.setItemValue(visibleSignatureConfiguration
						.getProfile().getSignerImageUri());
				visibleSignatureItem.setItemValue(itemValue);
			}
		}

		if (null != authorizedSubjects) {
			PolicyType policy = xacmlObjectFactory.createPolicyType();
			optionalInputs.getAny()
					.add(xacmlObjectFactory.createPolicy(policy));
			policy.setPolicyId("urn:" + UUID.randomUUID().toString());
			policy.setRuleCombiningAlgId("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides");
			TargetType target = xacmlObjectFactory.createTargetType();
			policy.setTarget(target);
			RuleType rule = xacmlObjectFactory.createRuleType();
			policy.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition()
					.add(rule);
			rule.setRuleId("whatever");
			rule.setEffect(EffectType.PERMIT);
			TargetType ruleTarget = xacmlObjectFactory.createTargetType();
			rule.setTarget(ruleTarget);
			SubjectsType subjects = xacmlObjectFactory.createSubjectsType();
			ruleTarget.setSubjects(subjects);
			for (String authorizedSubject : authorizedSubjects) {
				SubjectType subject = xacmlObjectFactory.createSubjectType();
				subjects.getSubject().add(subject);
				SubjectMatchType subjectMatch = xacmlObjectFactory
						.createSubjectMatchType();
				subject.getSubjectMatch().add(subjectMatch);
				subjectMatch
						.setMatchId("urn:oasis:names:tc:xacml:2.0:function:x500Name-regexp-match");
				AttributeValueType attributeValue = xacmlObjectFactory
						.createAttributeValueType();
				subjectMatch.setAttributeValue(attributeValue);
				attributeValue
						.setDataType("http://www.w3.org/2001/XMLSchema#string");
				attributeValue.getContent().add(authorizedSubject);
				SubjectAttributeDesignatorType subjectAttributeDesigator = xacmlObjectFactory
						.createSubjectAttributeDesignatorType();
				subjectMatch
						.setSubjectAttributeDesignator(subjectAttributeDesigator);
				subjectAttributeDesigator
						.setAttributeId("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
				subjectAttributeDesigator
						.setDataType("urn:oasis:names:tc:xacml:1.0:data-type:x500Name");
			}
			ResourcesType resources = xacmlObjectFactory.createResourcesType();
			ruleTarget.setResources(resources);
			ResourceType resource = xacmlObjectFactory.createResourceType();
			resources.getResource().add(resource);
			ResourceMatchType resourceMatch = xacmlObjectFactory
					.createResourceMatchType();
			resource.getResourceMatch().add(resourceMatch);
			resourceMatch
					.setMatchId("urn:oasis:names:tc:xacml:1.0:function:anyURI-equal");
			AttributeValueType resourceAttributeValue = xacmlObjectFactory
					.createAttributeValueType();
			resourceMatch.setAttributeValue(resourceAttributeValue);
			resourceAttributeValue
					.setDataType("http://www.w3.org/2001/XMLSchema#anyURI");
			resourceAttributeValue.getContent().add("urn:be:e-contract:dss");
			AttributeDesignatorType resourceAttributeDesignator = xacmlObjectFactory
					.createAttributeDesignatorType();
			resourceMatch
					.setResourceAttributeDesignator(resourceAttributeDesignator);
			resourceAttributeDesignator
					.setAttributeId("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
			resourceAttributeDesignator
					.setDataType("http://www.w3.org/2001/XMLSchema#anyURI");

			ActionsType actions = xacmlObjectFactory.createActionsType();
			ruleTarget.setActions(actions);
			ActionType action = xacmlObjectFactory.createActionType();
			actions.getAction().add(action);
			ActionMatchType actionMatch = xacmlObjectFactory
					.createActionMatchType();
			action.getActionMatch().add(actionMatch);
			actionMatch
					.setMatchId("urn:oasis:names:tc:xacml:1.0:function:string-equal");
			AttributeValueType actionAttributeValue = xacmlObjectFactory
					.createAttributeValueType();
			actionMatch.setAttributeValue(actionAttributeValue);
			actionAttributeValue
					.setDataType("http://www.w3.org/2001/XMLSchema#string");
			actionAttributeValue.getContent().add("sign");
			AttributeDesignatorType actionAttributeDesignator = xacmlObjectFactory
					.createAttributeDesignatorType();
			actionMatch.setActionAttributeDesignator(actionAttributeDesignator);
			actionAttributeDesignator
					.setAttributeId("urn:oasis:names:tc:xacml:1.0:action:action-id");
			actionAttributeDesignator
					.setDataType("http://www.w3.org/2001/XMLSchema#string");
		}

		// marshall to DOM
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder;
		try {
			documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}
		Document document = documentBuilder.newDocument();

		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(
							ObjectFactory.class,
							be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory.class,
							be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory.class,
							be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory.class,
							be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.marshal(pendingRequest, document);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}

		try {
			sign(document, session);
		} catch (Exception e) {
			throw new RuntimeException("error signing: " + e.getMessage(), e);
		}

		// marshall to base64 encoded
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException("JAXP config error: " + e.getMessage(),
					e);
		}
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			transformer.transform(new DOMSource(document), new StreamResult(
					outputStream));
		} catch (TransformerException e) {
			throw new RuntimeException("JAXP error: " + e.getMessage(), e);
		}
		String encodedPendingRequest = Base64
				.encode(outputStream.toByteArray());
		return encodedPendingRequest;
	}

	private static void sign(Document document,
			DigitalSignatureServiceSession session)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {
		Key key = new SecretKeySpec(session.getKey(), "HMACSHA1");
		Node parentElement = document.getElementsByTagNameNS(
				"urn:oasis:names:tc:dss:1.0:core:schema", "OptionalInputs")
				.item(0);
		DOMSignContext domSignContext = new DOMSignContext(key, parentElement);
		domSignContext.setDefaultNamespacePrefix("ds");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance("DOM");

		List<Transform> transforms = new LinkedList<Transform>();
		transforms.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED,
				(TransformParameterSpec) null));
		transforms.add(xmlSignatureFactory.newTransform(
				CanonicalizationMethod.EXCLUSIVE,
				(C14NMethodParameterSpec) null));
		Reference reference = xmlSignatureFactory.newReference("",
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null),
				transforms, null, null);

		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
				xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(SignatureMethod.HMAC_SHA1, null),
				Collections.singletonList(reference));

		Element securityTokenReferenceElement = getSecurityTokenReference(session);

		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		DOMStructure securityTokenReferenceDOMStructure = new DOMStructure(
				securityTokenReferenceElement);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(securityTokenReferenceDOMStructure));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
				signedInfo, keyInfo);
		xmlSignature.sign(domSignContext);
	}

	private static Element getSecurityTokenReference(
			DigitalSignatureServiceSession session) {
		be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory wsseObjectFactory = new be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory();

		SecurityTokenReferenceType securityTokenReference = wsseObjectFactory
				.createSecurityTokenReferenceType();
		ReferenceType reference = wsseObjectFactory.createReferenceType();
		reference
				.setValueType(DigitalSignatureServiceConstants.WS_SEC_CONV_TOKEN_TYPE);
		reference.setURI(session.getSecurityTokenId());
		securityTokenReference.getAny().add(
				wsseObjectFactory.createReference(reference));

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder;
		try {
			documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}
		Document document = documentBuilder.newDocument();

		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.marshal(wsseObjectFactory
					.createSecurityTokenReference(securityTokenReference),
					document);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		return document.getDocumentElement();
	}
}
