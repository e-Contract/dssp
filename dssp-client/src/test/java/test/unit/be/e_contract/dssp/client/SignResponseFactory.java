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
package test.unit.be.e_contract.dssp.client;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

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
import be.e_contract.dssp.ws.jaxb.dss.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.dss.Result;
import be.e_contract.dssp.ws.jaxb.dss.SignResponse;
import be.e_contract.dssp.ws.jaxb.saml.protocol.NameIdentifierType;
import be.e_contract.dssp.ws.jaxb.wsa.AttributedURIType;
import be.e_contract.dssp.ws.jaxb.wsa.RelatesToType;
import be.e_contract.dssp.ws.jaxb.wsse.ReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.SecurityTokenReferenceType;
import be.e_contract.dssp.ws.jaxb.wsu.AttributedDateTime;
import be.e_contract.dssp.ws.jaxb.wsu.TimestampType;

public class SignResponseFactory {

	private SignResponseFactory() {
		super();
	}

	public static String createSignResponse(String responseId,
			String destination, String inResponseTo, String tokenId,
			byte[] tokenKey) {
		return createSignResponse(responseId, destination, inResponseTo,
				tokenId, tokenKey,
				DigitalSignatureServiceConstants.PENDING_RESULT_MAJOR, null,
				null);
	}

	public static String createSignResponse(String responseId,
			String destination, String inResponseTo, String tokenId,
			byte[] tokenKey, String resultMajor, String resultMinor,
			String signerIdentity) {
		ObjectFactory dssObjectFactory = new ObjectFactory();
		be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory asyncObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory wsaObjectFactory = new be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory wsuObjectFactory = new be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory();
		be.e_contract.dssp.ws.jaxb.saml.protocol.ObjectFactory samlObjectFactory = new be.e_contract.dssp.ws.jaxb.saml.protocol.ObjectFactory();

		SignResponse signResponse = dssObjectFactory.createSignResponse();
		signResponse.setProfile(DigitalSignatureServiceConstants.PROFILE);
		Result result = dssObjectFactory.createResult();
		signResponse.setResult(result);
		result.setResultMajor(resultMajor);
		if (null != resultMinor) {
			result.setResultMinor(resultMinor);
		}

		AnyType optionalOutputs = dssObjectFactory.createAnyType();
		signResponse.setOptionalOutputs(optionalOutputs);

		optionalOutputs.getAny().add(
				asyncObjectFactory.createResponseID(responseId));

		RelatesToType relatesTo = wsaObjectFactory.createRelatesToType();
		optionalOutputs.getAny().add(
				wsaObjectFactory.createRelatesTo(relatesTo));
		relatesTo.setValue(inResponseTo);

		TimestampType timestamp = wsuObjectFactory.createTimestampType();
		optionalOutputs.getAny().add(
				wsuObjectFactory.createTimestamp(timestamp));
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

		AttributedURIType to = wsaObjectFactory.createAttributedURIType();
		optionalOutputs.getAny().add(wsaObjectFactory.createTo(to));
		to.setValue(destination);

		if (null != signerIdentity) {
			NameIdentifierType nameIdentifier = samlObjectFactory
					.createNameIdentifierType();
			nameIdentifier.setValue(signerIdentity);
			nameIdentifier
					.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
			optionalOutputs.getAny().add(
					dssObjectFactory.createSignerIdentity(nameIdentifier));
		}

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
			JAXBContext jaxbContext = JAXBContext.newInstance(
					ObjectFactory.class,
					be.e_contract.dssp.ws.jaxb.wsa.ObjectFactory.class,
					be.e_contract.dssp.ws.jaxb.wsu.ObjectFactory.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.marshal(signResponse, document);
		} catch (JAXBException ex) {
			throw new RuntimeException(ex);
		}
		try {
			sign(document, tokenId, tokenKey);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}

		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException("JAXP config error: " + e.getMessage(),
					e);
		}
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		try {
			transformer.transform(new DOMSource(document), new StreamResult(
					byteArrayOutputStream));
		} catch (TransformerException e) {
			throw new RuntimeException("JAXP error: " + e.getMessage(), e);
		}

		return Base64.encode(byteArrayOutputStream.toByteArray());
	}

	private static void sign(Document document, String tokenId, byte[] tokenKey)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {
		Key key = new SecretKeySpec(tokenKey, "HMACSHA1");
		Node parentElement = document.getElementsByTagNameNS(
				"urn:oasis:names:tc:dss:1.0:core:schema", "OptionalOutputs")
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

		Element securityTokenReferenceElement = getSecurityTokenReference(tokenId);

		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		DOMStructure securityTokenReferenceDOMStructure = new DOMStructure(
				securityTokenReferenceElement);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(securityTokenReferenceDOMStructure));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
				signedInfo, keyInfo);
		xmlSignature.sign(domSignContext);
	}

	private static Element getSecurityTokenReference(String tokenId) {
		be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory wsseObjectFactory = new be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory();

		SecurityTokenReferenceType securityTokenReference = wsseObjectFactory
				.createSecurityTokenReferenceType();
		ReferenceType reference = wsseObjectFactory.createReferenceType();
		reference
				.setValueType(DigitalSignatureServiceConstants.WS_SEC_CONV_TOKEN_TYPE);
		reference.setURI(tokenId);
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
