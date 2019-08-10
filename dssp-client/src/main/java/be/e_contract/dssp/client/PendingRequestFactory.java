/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2019 e-Contract.be BVBA.
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
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.e_contract.dssp.client.authorization.AuthorizedSubjectsSignatureAuthorization;
import be.e_contract.dssp.client.authorization.SignatureAuthorization;
import be.e_contract.dssp.client.impl.Utils;
import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.jaxb.dss.AnyType;
import be.e_contract.dssp.ws.jaxb.dss.KeySelector;
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
import be.e_contract.dssp.ws.jaxb.dssp.ItemValueStringsType;
import be.e_contract.dssp.ws.jaxb.dssp.ReturnKeySelectorType;
import be.e_contract.dssp.ws.jaxb.wsa.AttributedURIType;
import be.e_contract.dssp.ws.jaxb.wsa.EndpointReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.ReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.SecurityTokenReferenceType;
import be.e_contract.dssp.ws.jaxb.wsu.AttributedDateTime;
import be.e_contract.dssp.ws.jaxb.wsu.TimestampType;
import be.e_contract.dssp.ws.jaxb.xacml.policy.PolicyType;
import be.e_contract.dssp.ws.jaxb.xmldsig.KeyInfoType;

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
	 * @param session     the session object.
	 * @param destination the destination URL within your web application. This is
	 *                    where the DSS will return to.
	 * @param language    the optional language
	 * @return
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language) {
		return createPendingRequest(session, destination, language, null);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 *
	 * @param session                       the session object.
	 * @param destination                   the destination URL within your web
	 *                                      application. This is where the DSS will
	 *                                      return to.
	 * @param language                      the optional language
	 * @param visibleSignatureConfiguration the optional visible signature
	 *                                      configuration.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language, VisibleSignatureConfiguration visibleSignatureConfiguration) {
		return createPendingRequest(session, destination, language, visibleSignatureConfiguration, false,
				(SignatureAuthorization) null);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 * 
	 * <p>
	 * The content of the parameter {@code authorizedSubjects} can be constructed as
	 * follows. The {@code authorizedSubjects} parameter is a set of regular
	 * expressions. Suppose you have a national registration number that is allowed
	 * to sign, then you can construct the {@code authorizedSubjects} as follows.
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
	 * @param session                       the session object.
	 * @param destination                   the destination URL within your web
	 *                                      application. This is where the DSS will
	 *                                      return to.
	 * @param language                      the optional language
	 * @param visibleSignatureConfiguration the optional visible signature
	 *                                      configuration.
	 * @param returnSignerIdentity          indicates whether the DSS should return
	 *                                      the signatory's identity.
	 * @param authorizedSubjects            the optional signatory subject DNs that
	 *                                      are authorized to sign. An authorized
	 *                                      subject can be an regular expression.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language, VisibleSignatureConfiguration visibleSignatureConfiguration, boolean returnSignerIdentity,
			Set<String> authorizedSubjects) {
		SignatureAuthorization signatureAuthorization;
		if (null != authorizedSubjects) {
			signatureAuthorization = new AuthorizedSubjectsSignatureAuthorization(authorizedSubjects);
		} else {
			signatureAuthorization = null;
		}
		return createPendingRequest(session, destination, language, visibleSignatureConfiguration, returnSignerIdentity,
				signatureAuthorization);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 *
	 * @param session                       the session object.
	 * @param destination                   the destination URL within your web
	 *                                      application. This is where the DSS will
	 *                                      return to.
	 * @param language                      the optional language
	 * @param visibleSignatureConfiguration the optional visible signature
	 *                                      configuration.
	 * @param returnSignerIdentity          indicates whether the DSS should return
	 *                                      the signatory's identity.
	 * @param signatureAuthorization        the optional signature authorization
	 *                                      policy provider.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language, VisibleSignatureConfiguration visibleSignatureConfiguration, boolean returnSignerIdentity,
			SignatureAuthorization signatureAuthorization) {
		return createPendingRequest(session, destination, language, visibleSignatureConfiguration, returnSignerIdentity,
				signatureAuthorization, null);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 *
	 * @param session                       the session object.
	 * @param destination                   the destination URL within your web
	 *                                      application. This is where the DSS will
	 *                                      return to.
	 * @param language                      the optional language
	 * @param visibleSignatureConfiguration the optional visible signature
	 *                                      configuration.
	 * @param returnSignerIdentity          indicates whether the DSS should return
	 *                                      the signatory's identity.
	 * @param signatureAuthorization        the optional signature authorization
	 *                                      policy provider.
	 * @param tokens                        the optional signing token options that
	 *                                      should be presented to the signatory.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language, VisibleSignatureConfiguration visibleSignatureConfiguration, boolean returnSignerIdentity,
			SignatureAuthorization signatureAuthorization, Set<String> tokens) {
		return createPendingRequest(session, destination, language, visibleSignatureConfiguration, returnSignerIdentity,
				false, signatureAuthorization, tokens);
	}

	/**
	 * Creates the base64 encoded dss:PendingRequest element to be used for the
	 * Browser POST phase.
	 *
	 * @param session                       the session object.
	 * @param destination                   the destination URL within your web
	 *                                      application. This is where the DSS will
	 *                                      return to.
	 * @param language                      the optional language
	 * @param visibleSignatureConfiguration the optional visible signature
	 *                                      configuration.
	 * @param returnSignerIdentity          indicates whether the DSS should return
	 *                                      the signatory's identity.
	 * @param returnKeySelector             indicates whether the DSS should return
	 *                                      the used signatory's token identifier.
	 * @param signatureAuthorization        the optional signature authorization
	 *                                      policy provider.
	 * @param tokens                        the optional signing token options that
	 *                                      should be presented to the signatory.
	 * @return
	 * @see VisibleSignatureConfiguration
	 */
	public static String createPendingRequest(DigitalSignatureServiceSession session, String destination,
			String language, VisibleSignatureConfiguration visibleSignatureConfiguration, boolean returnSignerIdentity,
			boolean returnKeySelector, SignatureAuthorization signatureAuthorization, Set<String> tokens) {
		ObjectFactory asyncObjectFactory = new ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dss.ObjectFactory dssObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory wsaObjectFactory = new be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory wsuObjectFactory = new be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory vsObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory xacmlObjectFactory = new be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory dsspObjectFactory = new be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory();

		PendingRequest pendingRequest = asyncObjectFactory.createPendingRequest();
		pendingRequest.setProfile(DigitalSignatureServiceConstants.PROFILE);
		AnyType optionalInputs = dssObjectFactory.createAnyType();
		pendingRequest.setOptionalInputs(optionalInputs);

		optionalInputs.getAny()
				.add(dssObjectFactory.createAdditionalProfile(DigitalSignatureServiceConstants.DSS_ASYNC_PROFILE));
		optionalInputs.getAny().add(asyncObjectFactory.createResponseID(session.getResponseId()));

		if (null != language) {
			optionalInputs.getAny().add(dssObjectFactory.createLanguage(language));
		}

		if (returnSignerIdentity) {
			optionalInputs.getAny().add(dssObjectFactory.createReturnSignerIdentity(null));
		}

		if (returnKeySelector) {
			ReturnKeySelectorType returnKeySelectorOptionalInput = dsspObjectFactory.createReturnKeySelectorType();
			optionalInputs.getAny().add(dsspObjectFactory.createReturnKeySelector(returnKeySelectorOptionalInput));
		}

		if (null != tokens && !tokens.isEmpty()) {
			be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory dsObjectFactory = new be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory();
			for (String token : tokens) {
				KeySelector keySelector = dssObjectFactory.createKeySelector();
				KeyInfoType keyInfo = dsObjectFactory.createKeyInfoType();
				keyInfo.getContent().add(dsObjectFactory.createKeyName(token));
				keySelector.setKeyInfo(keyInfo);
				optionalInputs.getAny().add(keySelector);
			}
		}

		AttributedURIType messageId = wsaObjectFactory.createAttributedURIType();
		optionalInputs.getAny().add(wsaObjectFactory.createMessageID(messageId));
		String requestId = "uuid:" + UUID.randomUUID().toString();
		messageId.setValue(requestId);
		session.setInResponseTo(requestId);

		TimestampType timestamp = wsuObjectFactory.createTimestampType();
		optionalInputs.getAny().add(wsuObjectFactory.createTimestamp(timestamp));
		AttributedDateTime created = wsuObjectFactory.createAttributedDateTime();
		timestamp.setCreated(created);
		DateTimeFormatter dateTimeFormatter = ISODateTimeFormat.dateTime()
				.withChronology(ISOChronology.getInstanceUTC());
		DateTime createdDateTime = new DateTime();
		created.setValue(dateTimeFormatter.print(createdDateTime));
		AttributedDateTime expires = wsuObjectFactory.createAttributedDateTime();
		timestamp.setExpires(expires);
		DateTime expiresDateTime = createdDateTime.plusMinutes(5);
		expires.setValue(dateTimeFormatter.print(expiresDateTime));

		EndpointReferenceType replyTo = wsaObjectFactory.createEndpointReferenceType();
		optionalInputs.getAny().add(wsaObjectFactory.createReplyTo(replyTo));
		AttributedURIType address = wsaObjectFactory.createAttributedURIType();
		replyTo.setAddress(address);
		address.setValue(destination);
		session.setDestination(destination);

		if (null != visibleSignatureConfiguration) {
			VisibleSignatureConfigurationType visSigConfig = vsObjectFactory.createVisibleSignatureConfigurationType();
			optionalInputs.getAny().add(vsObjectFactory.createVisibleSignatureConfiguration(visSigConfig));
			VisibleSignaturePolicyType visibleSignaturePolicy = VisibleSignaturePolicyType.DOCUMENT_SUBMISSION_POLICY;
			visSigConfig.setVisibleSignaturePolicy(visibleSignaturePolicy);
			VisibleSignatureItemsConfigurationType visibleSignatureItemsConfiguration = vsObjectFactory
					.createVisibleSignatureItemsConfigurationType();
			visSigConfig.setVisibleSignatureItemsConfiguration(visibleSignatureItemsConfiguration);
			if (visibleSignatureConfiguration.getLocation() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(locationVisibleSignatureItem);
				locationVisibleSignatureItem.setItemName(ItemNameEnum.SIGNATURE_PRODUCTION_PLACE);
				ItemValueStringType itemValue = vsObjectFactory.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getLocation());
			}
			if (visibleSignatureConfiguration.getRole() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(locationVisibleSignatureItem);
				locationVisibleSignatureItem.setItemName(ItemNameEnum.SIGNATURE_REASON);
				ItemValueStringType itemValue = vsObjectFactory.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getRole());
			}
			if (visibleSignatureConfiguration.getSignerImageUri() != null) {
				PixelVisibleSignaturePositionType visibleSignaturePosition = vsObjectFactory
						.createPixelVisibleSignaturePositionType();
				visSigConfig.setVisibleSignaturePosition(visibleSignaturePosition);
				visibleSignaturePosition.setPageNumber(BigInteger.valueOf(visibleSignatureConfiguration.getPage()));
				visibleSignaturePosition.setX(BigInteger.valueOf(visibleSignatureConfiguration.getX()));
				visibleSignaturePosition.setY(BigInteger.valueOf(visibleSignatureConfiguration.getY()));

				VisibleSignatureItemType visibleSignatureItem = vsObjectFactory.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(visibleSignatureItem);
				visibleSignatureItem.setItemName(ItemNameEnum.SIGNER_IMAGE);
				ItemValueURIType itemValue = vsObjectFactory.createItemValueURIType();
				itemValue.setItemValue(visibleSignatureConfiguration.getSignerImageUri());
				visibleSignatureItem.setItemValue(itemValue);
			}
			if (visibleSignatureConfiguration.getCustomText() != null) {
				VisibleSignatureItemType customTextVisibleSignatureItem = vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(customTextVisibleSignatureItem);
				customTextVisibleSignatureItem.setItemName(ItemNameEnum.CUSTOM_TEXT);
				if (!visibleSignatureConfiguration.hasMultipleCustomText()) {
					ItemValueStringType itemValue = vsObjectFactory.createItemValueStringType();
					customTextVisibleSignatureItem.setItemValue(itemValue);
					itemValue.setItemValue(visibleSignatureConfiguration.getCustomText());
				} else {
					ItemValueStringsType itemValueStrings = dsspObjectFactory.createItemValueStringsType();
					customTextVisibleSignatureItem.setItemValue(itemValueStrings);
					itemValueStrings.setItemValue1(visibleSignatureConfiguration.getCustomText());
					itemValueStrings.setItemValue2(visibleSignatureConfiguration.getCustomText2());
					itemValueStrings.setItemValue3(visibleSignatureConfiguration.getCustomText3());
					itemValueStrings.setItemValue4(visibleSignatureConfiguration.getCustomText4());
					itemValueStrings.setItemValue5(visibleSignatureConfiguration.getCustomText5());
				}
			}
		}

		if (null != signatureAuthorization) {
			PolicyType policy = signatureAuthorization.getXACMLPolicy();
			optionalInputs.getAny().add(xacmlObjectFactory.createPolicy(policy));
		}

		// marshall to DOM
		DocumentBuilder documentBuilder = Utils.createSecureDocumentBuilder();
		Document document = documentBuilder.newDocument();

		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class,
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
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException("JAXP config error: " + e.getMessage(), e);
		}
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			transformer.transform(new DOMSource(document), new StreamResult(outputStream));
		} catch (TransformerException e) {
			throw new RuntimeException("JAXP error: " + e.getMessage(), e);
		}
		String encodedPendingRequest = Base64.encode(outputStream.toByteArray());
		return encodedPendingRequest;
	}

	private static void sign(Document document, DigitalSignatureServiceSession session) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Key key = new SecretKeySpec(session.getKey(), "HMACSHA1");
		Node parentElement = document.getElementsByTagNameNS("urn:oasis:names:tc:dss:1.0:core:schema", "OptionalInputs")
				.item(0);
		DOMSignContext domSignContext = new DOMSignContext(key, parentElement);
		domSignContext.setDefaultNamespacePrefix("ds");
		// XMLDSigRI Websphere work-around
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

		List<Transform> transforms = new LinkedList<>();
		transforms.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		transforms.add(
				xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null));
		Reference reference = xmlSignatureFactory.newReference("",
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null), transforms, null, null);

		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
				xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null),
				xmlSignatureFactory.newSignatureMethod(SignatureMethod.HMAC_SHA1, null),
				Collections.singletonList(reference));

		Element securityTokenReferenceElement = getSecurityTokenReference(session);

		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		DOMStructure securityTokenReferenceDOMStructure = new DOMStructure(securityTokenReferenceElement);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(securityTokenReferenceDOMStructure));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		xmlSignature.sign(domSignContext);
	}

	private static Element getSecurityTokenReference(DigitalSignatureServiceSession session) {
		be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory wsseObjectFactory = new be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory();

		SecurityTokenReferenceType securityTokenReference = wsseObjectFactory.createSecurityTokenReferenceType();
		ReferenceType reference = wsseObjectFactory.createReferenceType();
		reference.setValueType(DigitalSignatureServiceConstants.WS_SEC_CONV_TOKEN_TYPE);
		reference.setURI(session.getSecurityTokenId());
		securityTokenReference.getAny().add(wsseObjectFactory.createReference(reference));

		DocumentBuilder documentBuilder = Utils.createSecureDocumentBuilder();
		Document document = documentBuilder.newDocument();

		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.marshal(wsseObjectFactory.createSecurityTokenReference(securityTokenReference), document);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		return document.getDocumentElement();
	}
}
