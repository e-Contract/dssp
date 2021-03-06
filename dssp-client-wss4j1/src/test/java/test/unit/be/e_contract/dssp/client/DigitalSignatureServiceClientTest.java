/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2020 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.xml.ws.Endpoint;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;
import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.SignatureType;
import be.e_contract.dssp.client.TwoStepSession;
import be.e_contract.dssp.client.VerificationResult;
import be.e_contract.dssp.client.VisibleSignatureConfiguration;
import be.e_contract.dssp.client.attestation.DownloadResult;

public class DigitalSignatureServiceClientTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(DigitalSignatureServiceClientTest.class);

	private Endpoint endpoint;

	private DigitalSignatureServiceClient client;

	private DigitalSignatureServiceTestPort testPort;

	@BeforeEach
	public void setUp() throws Exception {
		this.testPort = new DigitalSignatureServiceTestPort();
		this.endpoint = Endpoint.create(this.testPort);
		String address = "http://localhost:" + getFreePort() + "/dss";
		this.endpoint.publish(address);

		this.client = new DigitalSignatureServiceClient(address);
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.endpoint.stop();
	}

	@Test
	public void testClient() throws Exception {
		// operate
		this.testPort.reset();
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
	}

	@Test
	public void testClientAuthentication() throws Exception {
		// operate
		this.testPort.reset();
		CallbackTestHandler.password = "app-password";
		this.client.setCredentials("app-username", "app-password");
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
	}

	@Test
	public void testClientX509Authentication() throws Exception {
		// setup
		KeyPair keyPair = TestUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test");
		// operate
		this.testPort.reset();
		this.client.setCredentials(privateKey, certificate);
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
		assertEquals(certificate, TestCrypto.getCertificate());
	}

	@Test
	public void testClientSAMLAuthentication() throws Exception {
		// setup
		KeyPair keyPair = TestUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test");
		Element samlAssertion = TestUtils.generateSAMLAssertion(privateKey, certificate, "SAML Issuer", "Subject Name");
		assertNotNull(samlAssertion);

		// operate
		this.testPort.reset();
		this.client.setCredentials(samlAssertion);
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
		assertEquals(certificate, TestCrypto.getCertificate());
	}

	@Test
	public void testClientHOKSAMLAuthentication() throws Exception {
		// setup
		KeyPair keyPair = TestUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test");
		KeyPair hokKeyPair = TestUtils.generateKeyPair();
		PublicKey hokPublicKey = hokKeyPair.getPublic();
		PrivateKey hokPrivateKey = hokKeyPair.getPrivate();
		Element samlAssertion = TestUtils.generateHOKSAMLAssertion(privateKey, certificate, "SAML Issuer",
				"Subject Name", hokPublicKey);
		assertNotNull(samlAssertion);

		// operate
		this.testPort.reset();
		this.client.setCredentials(samlAssertion, hokPrivateKey);
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
		assertEquals(certificate, TestCrypto.getCertificate());
	}

	@Test
	public void testClientSAMLWithAuthorizationAuthentication() throws Exception {
		// setup
		byte[] document = "hello world".getBytes();

		KeyPair keyPair = TestUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test");

		Element samlAssertion = TestUtils.generateSAMLAssertion(privateKey, certificate, "SAML Issuer", "Subject Name",
				document);
		assertNotNull(samlAssertion);

		// operate
		this.testPort.reset();
		this.client.setCredentials(samlAssertion);
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				document);

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertFalse(this.testPort.hasReceivedAttachment());
		assertEquals(certificate, TestCrypto.getCertificate());
	}

	@Test
	public void testClientAttachment() throws Exception {
		// operate
		this.testPort.reset();
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes(), true);

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
		assertTrue(this.testPort.hasReceivedAttachment());
	}

	@Test
	public void testDownloadSignedDocument() throws Exception {
		// setup
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());
		LOGGER.debug("has token key: {}", (null != session.getKey()));
		session.setSignResponseVerified(true);
		CallbackTestHandler.tokenKey = session.getKey();

		// operate
		byte[] signedDocument = this.client.downloadSignedDocument(session);

		// verify
		assertNotNull(signedDocument);
	}

	@Test
	public void testUnverifiedSignResponse() throws Exception {
		// setup
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());
		LOGGER.debug("has token key: {}", (null != session.getKey()));
		CallbackTestHandler.tokenKey = session.getKey();

		// operate
		try {
			this.client.downloadSignedDocument(session);
			fail();
		} catch (SecurityException e) {
			// expected
			LOGGER.debug("expected exception: {}", e.getMessage());
		}
	}

	@Test
	public void testDownloadSignedDocumentAsAttachment() throws Exception {
		// setup
		this.testPort.setUseAttachments(true);
		DigitalSignatureServiceSession session = this.client.uploadDocument("text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes());
		session.setSignResponseVerified(true);
		LOGGER.debug("has token key: {}", (null != session.getKey()));
		CallbackTestHandler.tokenKey = session.getKey();

		// operate
		byte[] signedDocument = this.client.downloadSignedDocument(session);

		// verify
		assertNotNull(signedDocument);
	}

	@Test
	public void testVerifyDocument() throws Exception {
		// operate
		VerificationResult verificationResult = this.client.verify("text/plain", "hello world".getBytes(), false);

		// verify
		assertNotNull(verificationResult);
		assertNotNull(verificationResult.getSignatureInfos());
		assertNotNull(verificationResult.getRenewTimeStampBefore());
		assertEquals(1, verificationResult.getSignatureInfos().size());
		assertEquals("CN=Subject", verificationResult.getSignatureInfos().get(0).getName());
	}

	@Test
	public void testESeal() throws Exception {
		// setup
		KeyPair keyPair = TestUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test");

		VisibleSignatureConfiguration visibleSignatureConfiguration = new VisibleSignatureConfiguration();
		visibleSignatureConfiguration.setLocation("location");
		visibleSignatureConfiguration.setRole("role");

		// operate
		this.testPort.reset();
		this.client.setCredentials(privateKey, certificate);
		DownloadResult downloadResult = this.client.eSeal("text/plain", "hello world".getBytes(), "key-name", false,
				SignatureType.PADES_BASELINE, visibleSignatureConfiguration, true);

		// verify
		assertNotNull(downloadResult);
		assertNotNull(downloadResult.getSignedDocument());
	}

	@Test
	public void testLocalSigTwoStepApproach() throws Exception {
		// prepare
		this.testPort.reset();

		KeyPair keyPair = TestUtils.generateKeyPair();
		X509Certificate certificate = TestUtils.generateCertificate(keyPair, "CN=Test Signing Certificate");
		List<X509Certificate> certificateChain = new LinkedList<>();
		certificateChain.add(certificate);
		certificateChain.add(certificate);

		// operate
		TwoStepSession session = this.client.prepareSignature("text/plain", "hello world".getBytes(), null, false,
				certificateChain);

		// verify
		assertNotNull(session);
		assertNotNull(session.getCorrelationId());
		LOGGER.debug("correction ID: {}", session.getCorrelationId());
		assertEquals("SHA-256", session.getDigestAlgo());
		assertNotNull(session.getDigestValue());

		// operate
		byte[] signedDocument = this.client.performSignature(session, "signature value".getBytes());

		// verify
		assertNotNull(signedDocument);
	}

	@Test
	public void testUpdateSignature() throws Exception {
		// setup
		this.testPort.reset();

		// operate
		DownloadResult downloadResult = this.client.updateSignature("text/plain", "hello world".getBytes(),
				SignatureType.PADES_BASELINE, false);

		// verify
		assertNotNull(downloadResult);
		assertNotNull(downloadResult.getSignedDocument());
	}

	private int getFreePort() throws IOException {
		ServerSocket server = new ServerSocket(0);
		int port = server.getLocalPort();
		server.close();
		return port;
	}
}
