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

package test.unit.be.e_contract.dssp.client;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.xml.namespace.QName;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

public class TestUtils {

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}

	public static X509Certificate generateCertificate(KeyPair keyPair, String distinguishedName) throws Exception {
		X500Name issuerX500Name = new X500Name(distinguishedName);
		X500Name subjectX500Name = new X500Name(distinguishedName);

		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

		SecureRandom secureRandom = new SecureRandom();
		byte[] serialValue = new byte[8];
		secureRandom.nextBytes(serialValue);
		BigInteger serial = new BigInteger(serialValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerX500Name, serial,
				notBefore.toDate(), notAfter.toDate(), subjectX500Name, publicKeyInfo);

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));
		return certificate;
	}

	public static Element generateSAMLAssertion(PrivateKey privateKey, X509Certificate certificate, String issuerName,
			String subjectName) throws MarshallingException, SecurityException, SignatureException {
		Assertion assertion = buildXMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setVersion(SAMLVersion.VERSION_20);
		String assertionId = "assertion-" + UUID.randomUUID().toString();
		assertion.setID(assertionId);
		DateTime issueInstant = new DateTime();
		assertion.setIssueInstant(issueInstant);

		Issuer issuer = buildXMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		assertion.setIssuer(issuer);
		issuer.setValue(issuerName);

		Subject subject = buildXMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		assertion.setSubject(subject);
		NameID subjectNameId = buildXMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		subject.setNameID(subjectNameId);
		subjectNameId.setValue(subjectName);
		SubjectConfirmation subjectConfirmation = buildXMLObject(SubjectConfirmation.class,
				SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		BasicX509Credential credential = new BasicX509Credential();
		credential.setPrivateKey(privateKey);
		credential.setEntityCertificate(certificate);

		Signature signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(credential);
		SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
		SecurityHelper.prepareSignatureParams(signature, credential, secConfig, null);

		assertion.setSignature(signature);

		Element element = Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);

		Signer.signObject(signature);

		return element;
	}

	public static <T extends XMLObject> T buildXMLObject(Class<T> clazz, QName objectQName) {
		XMLObjectBuilder<T> builder = Configuration.getBuilderFactory().getBuilder(objectQName);
		if (builder == null) {
			throw new RuntimeException("Unable to retrieve builder for object QName " + objectQName);
		}
		return builder.buildObject(objectQName);
	}
}
