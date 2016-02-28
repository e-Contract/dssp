/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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
package be.e_contract.dssp.client.attestation;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import be.e_contract.dssp.client.impl.SAMLKeySelector;
import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.jaxb.saml.assertion.AssertionType;
import be.e_contract.dssp.ws.jaxb.saml.assertion.AttributeStatementType;
import be.e_contract.dssp.ws.jaxb.saml.assertion.AttributeType;
import be.e_contract.dssp.ws.jaxb.saml.assertion.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.saml.assertion.StatementAbstractType;

/**
 * A parser and validator for attestation SAML assertions.
 * 
 * @author Frank Cornelis
 *
 */
public class AttestationParser {

	public static final String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

	private final Element attestation;

	private final X509Certificate issuerCertificate;

	private final String issuerName;

	private final Date issueInstant;

	private final byte[] documentDigest;

	private final byte[] signedDocumentDigest;

	/**
	 * Main constructor.
	 * 
	 * @param attestation
	 *            the attestation SAML assertion as DOM element.
	 * @throws Exception
	 */
	public AttestationParser(Element attestation) throws Exception {
		this.attestation = attestation;

		NodeList signatureNodeList = attestation.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Signature");
		if (signatureNodeList.getLength() == 0) {
			throw new SecurityException("missing XML signature");
		}
		Element signatureElement = (Element) signatureNodeList.item(0);

		attestation.setIdAttribute("ID", true);

		SAMLKeySelector samlKeySelector = new SAMLKeySelector();
		DOMValidateContext domValidateContext = new DOMValidateContext(samlKeySelector, signatureElement);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
		XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);

		boolean validSignature = xmlSignature.validate(domValidateContext);
		if (!validSignature) {
			throw new SecurityException("invalid XML signature");
		}

		String assertionId = attestation.getAttribute("ID");

		SignedInfo signedInfo = xmlSignature.getSignedInfo();
		List<Reference> references = signedInfo.getReferences();
		if (references.size() != 1) {
			throw new SecurityException("ds:SignedInfo should contain only 1 ds:Reference");
		}
		Reference reference = references.get(0);
		if (reference.getURI() != null && !reference.getURI().isEmpty()) {
			if (reference.getURI().length() < 2) {
				throw new SecurityException("ds:Reference URI incorrect");
			}
			if (!reference.getURI().substring(1).equals(assertionId)) {
				throw new SecurityException("ds:Reference URI incorrect");
			}
		}
		List<Transform> transforms = reference.getTransforms();
		if (transforms.size() > 2) {
			throw new SecurityException("incorrect number of ds:Transforms");
		}
		boolean hasEnveloped = false;
		for (Transform transform : transforms) {
			if (transform.getAlgorithm().equals(Transform.ENVELOPED)) {
				hasEnveloped = true;
			} else if (!transform.getAlgorithm().equals(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
					&& !transform.getAlgorithm().equals(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS)) {
				throw new SecurityException("invalid Transform");
			}
		}
		if (!hasEnveloped) {
			throw new SecurityException("no Enveloped transform");
		}

		this.issuerCertificate = samlKeySelector.getCertificate();

		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<AssertionType> assertionJAXBElement = (JAXBElement<AssertionType>) unmarshaller
				.unmarshal(attestation);
		AssertionType assertion = assertionJAXBElement.getValue();
		this.issuerName = assertion.getIssuer().getValue();

		this.issueInstant = assertion.getIssueInstant().toGregorianCalendar().getTime();

		byte[] documentDigest = null;
		byte[] signedDocumentDigest = null;
		List<StatementAbstractType> statements = assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement();
		for (StatementAbstractType statement : statements) {
			if (statement instanceof AttributeStatementType) {
				AttributeStatementType attributeStatement = (AttributeStatementType) statement;
				List<Object> attributeObjects = attributeStatement.getAttributeOrEncryptedAttribute();
				for (Object attributeObject : attributeObjects) {
					if (attributeObject instanceof AttributeType) {
						AttributeType attribute = (AttributeType) attributeObject;
						if (attribute.getName().equals(
								DigitalSignatureServiceConstants.DOCUMENT_DIGEST_ATTESTATION_SAML_ATTRIBUTE_NAME)) {
							documentDigest = (byte[]) attribute.getAttributeValue().get(0);
						} else if (attribute.getName().equals(
								DigitalSignatureServiceConstants.SIGNED_DOCUMENT_DIGEST_ATTESTATION_SAML_ATTRIBUTE_NAME)) {
							signedDocumentDigest = (byte[]) attribute.getAttributeValue().get(0);
						}
					}
				}
			}
		}
		this.documentDigest = documentDigest;
		this.signedDocumentDigest = signedDocumentDigest;
	}

	/**
	 * Gives back the original attestation SAML assertion as DOM element.
	 * 
	 * @return
	 */
	public Element getElement() {
		return this.attestation;
	}

	/**
	 * Gives back the issuer certificate that signed the attestation SAML
	 * assertion.
	 * 
	 * @return the X509 certificate of the attestation issuer.
	 */
	public X509Certificate getIssuerCertificate() {
		return this.issuerCertificate;
	}

	/**
	 * Gives back the human-readable name of the attestation issuer.
	 * 
	 * @return
	 */
	public String getIssuerName() {
		return this.issuerName;
	}

	/**
	 * Gives back the timestamp of creation of the attestation SAML assertion.
	 * 
	 * @return
	 */
	public Date getIssueInstant() {
		return this.issueInstant;
	}

	/**
	 * Gives back the SHA-256 digest value of the original to be signed
	 * document.
	 * 
	 * @return
	 */
	public byte[] getDocumentDigest() {
		return this.documentDigest;
	}

	/**
	 * Gives back the SHA-256 digest value of the signed document.
	 * 
	 * @return
	 */
	public byte[] getSignedDocumentDigest() {
		return this.signedDocumentDigest;
	}

	/**
	 * Verifies an original document against the statements within this
	 * attestation SAML assertion.
	 * 
	 * @param document
	 *            the original document.
	 * @throws Exception
	 */
	public void verifyDocument(byte[] document) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(document);
		byte[] actualDigestValue = messageDigest.digest();
		if (!Arrays.equals(actualDigestValue, this.documentDigest)) {
			throw new SecurityException("incorrect digest value");
		}
	}

	/**
	 * Verifies a signed document against the statements within this attestation
	 * SAML assertion.
	 * 
	 * @param document
	 * @throws Exception
	 */
	public void verifySignedDocument(byte[] document) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(document);
		byte[] actualDigestValue = messageDigest.digest();
		if (!Arrays.equals(actualDigestValue, this.signedDocumentDigest)) {
			throw new SecurityException("incorrect digest value");
		}
	}
}
