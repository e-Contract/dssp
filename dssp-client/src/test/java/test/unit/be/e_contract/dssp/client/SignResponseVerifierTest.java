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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.SecureRandom;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import be.e_contract.dssp.client.ClientRuntimeException;
import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.SignResponseVerificationResult;
import be.e_contract.dssp.client.SignResponseVerifier;
import be.e_contract.dssp.client.SubjectNotAuthorizedException;
import be.e_contract.dssp.client.UserCancelException;
import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;

public class SignResponseVerifierTest {

	private static final Log LOG = LogFactory
			.getLog(SignResponseVerifierTest.class);

	@Test
	public void testVerifierSignResponse() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		SignResponseVerificationResult result = SignResponseVerifier
				.checkSignResponse(signResponse, session);

		assertTrue(session.isSignResponseVerified());
		assertNotNull(result);
	}

	@Test
	public void testSignerIdentity() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey,
				DigitalSignatureServiceConstants.PENDING_RESULT_MAJOR, null,
				"signer-identity");
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		SignResponseVerificationResult result = SignResponseVerifier
				.checkSignResponse(signResponse, session);

		assertTrue(session.isSignResponseVerified());
		assertNotNull(result);
		assertEquals("signer-identity", result.getSignerIdentity());
	}

	@Test
	public void testNullSession() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);

		try {
			SignResponseVerifier.checkSignResponse(signResponse, null);
			fail();
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testMessageIDDoesNotMatch() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id-foobar", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testReplyToNotMatch() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to-foobar");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testDestinationDoesNotMatch() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination-foobar");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testTokenKeyDoesNotMatch() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", "foobar-token-key".getBytes(), null);
		session.setDestination("destination-foobar");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testMissingSignature() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey);
		LOG.debug("SignResponse: " + signResponse);

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(new ByteArrayInputStream(
				Base64.decode(signResponse)));
		Node signatureNode = document.getElementsByTagNameNS(
				"http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
		signatureNode.getParentNode().removeChild(signatureNode);

		signResponse = Base64.encode(toString(document).getBytes());

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testNoXML() throws Exception {
		String signResponse = Base64.encode("foobar".getBytes());

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", "foobar-token-key".getBytes(), null);
		session.setDestination("destination-foobar");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testNoBase64() throws Exception {
		String signResponse = "foobar";

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", "foobar-token-key".getBytes(), null);
		session.setDestination("destination-foobar");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SecurityException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertFalse(session.isSignResponseVerified());
		}
	}

	@Test
	public void testUserCancel() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory
				.createSignResponse(
						"response-id",
						"destination",
						"in-response-to",
						"token-id",
						tokenKey,
						DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR,
						DigitalSignatureServiceConstants.USER_CANCEL_RESULT_MINOR,
						null);
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (UserCancelException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
		}
	}

	@Test
	public void testAuthorization() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory
				.createSignResponse(
						"response-id",
						"destination",
						"in-response-to",
						"token-id",
						tokenKey,
						DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR,
						DigitalSignatureServiceConstants.SUBJECT_NOT_AUTHORIZED_RESULT_MINOR,
						null);
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SubjectNotAuthorizedException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
		}
	}

	@Test
	public void testAuthorizationWithSignerIdentity() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory
				.createSignResponse(
						"response-id",
						"destination",
						"in-response-to",
						"token-id",
						tokenKey,
						DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR,
						DigitalSignatureServiceConstants.SUBJECT_NOT_AUTHORIZED_RESULT_MINOR,
						"signer-identity");
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (SubjectNotAuthorizedException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
			assertEquals("signer-identity", e.getSignerIdentity());
		}
	}

	@Test
	public void testClientRuntime() throws Exception {
		byte[] tokenKey = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(tokenKey);
		String signResponse = SignResponseFactory.createSignResponse(
				"response-id", "destination", "in-response-to", "token-id",
				tokenKey,
				DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR,
				DigitalSignatureServiceConstants.CLIENT_RUNTIME_RESULT_MINOR,
				null);
		LOG.debug("SignResponse: " + signResponse);

		LOG.debug("decoded sign response: "
				+ new String(Base64.decode(signResponse.getBytes())));

		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response-id", "token-id", tokenKey, null);
		session.setDestination("destination");
		session.setInResponseTo("in-response-to");
		try {
			SignResponseVerifier.checkSignResponse(signResponse, session);
			fail();
		} catch (ClientRuntimeException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// expected
		}
	}

	public static String toString(Node node) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		StringWriter stringWriter = new StringWriter();
		transformer.transform(new DOMSource(node), new StreamResult(
				stringWriter));
		return stringWriter.toString();
	}
}
