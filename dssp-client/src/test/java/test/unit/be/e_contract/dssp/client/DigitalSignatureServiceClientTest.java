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

package test.unit.be.e_contract.dssp.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.ws.Endpoint;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;
import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.SignatureType;
import be.e_contract.dssp.client.VerificationResult;

public class DigitalSignatureServiceClientTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(DigitalSignatureServiceClientTest.class);

	private Endpoint endpoint;

	private DigitalSignatureServiceClient client;

	private DigitalSignatureServiceTestPort testPort;

	@Before
	public void setUp() throws Exception {
		this.testPort = new DigitalSignatureServiceTestPort();
		this.endpoint = Endpoint.create(this.testPort);
		String address = "http://localhost:" + getFreePort() + "/dss";
		this.endpoint.publish(address);

		this.client = new DigitalSignatureServiceClient(address);
	}

	@After
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

	private int getFreePort() throws IOException {
		ServerSocket server = new ServerSocket(0);
		int port = server.getLocalPort();
		server.close();
		return port;
	}
}
