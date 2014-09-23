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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.ServerSocket;

import javax.xml.ws.Endpoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;
import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.SignatureType;
import be.e_contract.dssp.client.VerificationResult;

public class DigitalSignatureServiceClientTest {

	private static final Log LOG = LogFactory
			.getLog(DigitalSignatureServiceClientTest.class);

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
		DigitalSignatureServiceSession session = this.client
				.uploadDocument("text/plain", SignatureType.XADES_X_L,
						"hello world".getBytes());

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
	}

	@Test
	public void testClientAttachment() throws Exception {
		// operate
		DigitalSignatureServiceSession session = this.client.uploadDocument(
				"text/plain", SignatureType.XADES_X_L,
				"hello world".getBytes(), true);

		// verify
		assertNotNull(session);
		assertNotNull(session.getResponseId());
		assertNotNull(session.getSecurityTokenId());
		assertNotNull(session.getKey());
	}

	@Test
	public void testDownloadSignedDocument() throws Exception {
		// setup
		DigitalSignatureServiceSession session = this.client
				.uploadDocument("text/plain", SignatureType.XADES_X_L,
						"hello world".getBytes());
		LOG.debug("has token key: " + (null != session.getKey()));
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
		DigitalSignatureServiceSession session = this.client
				.uploadDocument("text/plain", SignatureType.XADES_X_L,
						"hello world".getBytes());
		LOG.debug("has token key: " + (null != session.getKey()));
		CallbackTestHandler.tokenKey = session.getKey();

		// operate
		try {
			this.client.downloadSignedDocument(session);
			fail();
		} catch (SecurityException e) {
			// expected
			LOG.debug("expected exception: " + e.getMessage());
		}
	}

	@Test
	public void testDownloadSignedDocumentAsAttachment() throws Exception {
		// setup
		this.testPort.setUseAttachments(true);
		DigitalSignatureServiceSession session = this.client
				.uploadDocument("text/plain", SignatureType.XADES_X_L,
						"hello world".getBytes());
		session.setSignResponseVerified(true);
		LOG.debug("has token key: " + (null != session.getKey()));
		CallbackTestHandler.tokenKey = session.getKey();

		// operate
		byte[] signedDocument = this.client.downloadSignedDocument(session);

		// verify
		assertNotNull(signedDocument);
	}

	@Test
	public void testVerifyDocument() throws Exception {
		// operate
		VerificationResult verificationResult = this.client.verify(
				"text/plain", "hello world".getBytes(), false);

		// verify
		assertNotNull(verificationResult);
		assertNotNull(verificationResult.getSignatureInfos());
		assertNotNull(verificationResult.getRenewTimeStampBefore());
		assertEquals(1, verificationResult.getSignatureInfos().size());
		assertEquals("CN=Subject", verificationResult.getSignatureInfos()
				.get(0).getName());
	}

	private int getFreePort() throws IOException {
		ServerSocket server = new ServerSocket(0);
		int port = server.getLocalPort();
		server.close();
		return port;
	}
}
