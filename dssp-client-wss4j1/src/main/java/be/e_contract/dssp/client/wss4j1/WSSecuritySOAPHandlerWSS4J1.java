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

package be.e_contract.dssp.client.wss4j1;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.spi.WSSecuritySOAPHandler;

/**
 * WS-Security JAX-WS SOAP handler based on WSS4J version 1.x. Creates a
 * WS-Security signature using the WS-SecureConversation security token or a
 * WS-Security username/password header.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSSecuritySOAPHandlerWSS4J1 implements WSSecuritySOAPHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSSecuritySOAPHandlerWSS4J1.class);

	private DigitalSignatureServiceSession session;

	private String username;

	private String password;

	private PrivateKey privateKey;

	private X509Certificate certificate;

	private Element samlAssertion;

	private void resetCredentials() {
		this.session = null;
		this.username = null;
		this.password = null;
		this.privateKey = null;
		this.certificate = null;
		this.samlAssertion = null;
	}

	/**
	 * Sets the session object to be used for constructing the WS-Security SOAP
	 * header.
	 * 
	 * @param session
	 */
	@Override
	public void setSession(DigitalSignatureServiceSession session) {
		resetCredentials();
		this.session = session;
	}

	/**
	 * Sets the WS-Security username/password credentials.
	 * 
	 * @param username
	 * @param password
	 */
	@Override
	public void setCredentials(String username, String password) {
		resetCredentials();
		this.username = username;
		this.password = password;
	}

	/**
	 * Sets the WS-Security X509 credentials.
	 *
	 * @param privateKey  the private key.
	 * @param certificate the X509 certificate.
	 */
	@Override
	public void setCredentials(PrivateKey privateKey, X509Certificate certificate) {
		resetCredentials();
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	/**
	 * Sets the WS-Security bearer SAML credentials.
	 *
	 * @param samlAssertion the DOM element representing the SAML assertion.
	 */
	@Override
	public void setCredentials(Element samlAssertion) {
		resetCredentials();
		this.samlAssertion = samlAssertion;
	}

	/**
	 * Sets the WS-Security holder-of-key SAML credentials.
	 *
	 * @param samlAssertion the DOM element representing the SAML assertion.
	 * @param privateKey    the proof-of-possession key.
	 */
	@Override
	public void setCredentials(Element samlAssertion, PrivateKey privateKey) {
		resetCredentials();
		this.samlAssertion = samlAssertion;
		this.privateKey = privateKey;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		if (true == outboundProperty.booleanValue()) {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				LOGGER.error("outbound exception: " + e.getMessage(), e);
				throw new ProtocolException(e);
			}
		}
		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context) throws WSSecurityException, SOAPException {
		if (null == this.session && null == this.username && null == this.privateKey && null == this.samlAssertion) {
			return;
		}
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		SOAPHeader soapHeader;
		try {
			soapHeader = soapMessage.getSOAPHeader();
		} catch (SOAPException e) {
			// WebSphere 8.5.5.1 work-around.
			soapHeader = null;
		}
		if (null == soapHeader) {
			/*
			 * Work-around for Axis2.
			 */
			SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
			soapHeader = soapEnvelope.addHeader();
		}

		WSSecHeader wsSecHeader = new WSSecHeader();
		Element securityElement = wsSecHeader.insertSecurityHeader(soapPart);

		if (null != this.session) {
			securityElement.appendChild(
					securityElement.getOwnerDocument().importNode(this.session.getSecurityTokenElement(), true));
		}

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp();
		wsSecTimeStamp.setTimeToLive(60);
		wsSecTimeStamp.build(soapPart, wsSecHeader);

		if (null != this.username) {
			WSSecUsernameToken usernameToken = new WSSecUsernameToken();
			usernameToken.setUserInfo(this.username, this.password);
			usernameToken.setPasswordType(WSConstants.PASSWORD_DIGEST);
			usernameToken.prepare(soapPart);
			usernameToken.prependToHeader(wsSecHeader);
		}

		if (null != this.privateKey && null == this.samlAssertion) {
			// work-around for WebSphere
			WSSConfig wssConfig = new WSSConfig();
			wssConfig.setWsiBSPCompliant(false);

			WSSecSignature wsSecSignature = new WSSecSignature(wssConfig);
			wsSecSignature.setSignatureAlgorithm(WSConstants.RSA_SHA1);
			wsSecSignature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
			Crypto crypto = new WSSecurityCrypto(this.privateKey, this.certificate);
			wsSecSignature.prepare(soapPart, crypto, wsSecHeader);
			wsSecSignature.appendBSTElementToHeader(wsSecHeader);
			wsSecSignature.setSignatureAlgorithm(WSConstants.RSA);
			wsSecSignature.setDigestAlgo(Constants.ALGO_ID_DIGEST_SHA1);
			Vector<WSEncryptionPart> signParts = new Vector<>();
			SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
			signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(),
					soapConstants.getEnvelopeURI(), "Content"));
			signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
			List<Reference> referenceList = wsSecSignature.addReferencesToSign(signParts, wsSecHeader);
			wsSecSignature.computeSignature(referenceList, false, null);
		}

		if (null != this.session) {
			// work-around for WebSphere
			WSSConfig wssConfig = new WSSConfig();
			wssConfig.setWsiBSPCompliant(false);

			WSSecSignature wsSecSignature = new WSSecSignature(wssConfig);
			wsSecSignature.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
			wsSecSignature.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
			wsSecSignature.setCustomTokenId(this.session.getSecurityTokenElement().getAttributeNS(
					"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id"));
			wsSecSignature.setSecretKey(this.session.getKey());
			wsSecSignature.prepare(soapPart, null, wsSecHeader);
			Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
			SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
			signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(),
					soapConstants.getEnvelopeURI(), "Content"));
			signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
			List<Reference> referenceList = wsSecSignature.addReferencesToSign(signParts, wsSecHeader);
			wsSecSignature.computeSignature(referenceList, false, null);
		}

		if (null != this.samlAssertion) {
			LOGGER.debug("adding SAML assertion");
			securityElement.appendChild(securityElement.getOwnerDocument().importNode(this.samlAssertion, true));
			if (null != this.privateKey) {
				// holder-of-key SAML
				// work-around for WebSphere
				WSSConfig wssConfig = new WSSConfig();
				wssConfig.setWsiBSPCompliant(false);

				WSSecSignature wsSecSignature = new WSSecSignature(wssConfig);
				wsSecSignature.setSignatureAlgorithm(WSConstants.RSA_SHA1);
				wsSecSignature.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
				wsSecSignature.setCustomTokenValueType(WSConstants.WSS_SAML2_KI_VALUE_TYPE);
				String samlId = this.samlAssertion.getAttribute("ID");
				wsSecSignature.setCustomTokenId(samlId);
				Crypto crypto = new WSSecurityCrypto(this.privateKey, null);
				wsSecSignature.prepare(soapPart, crypto, wsSecHeader);
				wsSecSignature.appendBSTElementToHeader(wsSecHeader);
				wsSecSignature.setSignatureAlgorithm(WSConstants.RSA);
				wsSecSignature.setDigestAlgo(Constants.ALGO_ID_DIGEST_SHA1);
				Vector<WSEncryptionPart> signParts = new Vector<>();
				SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
				signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(),
						soapConstants.getEnvelopeURI(), "Content"));
				signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
				List<Reference> referenceList = wsSecSignature.addReferencesToSign(signParts, wsSecHeader);
				wsSecSignature.computeSignature(referenceList, false, null);
			}
		}

		/*
		 * Really needs to be at the end for Axis2 to work. Axiom bug?
		 */
		appendSecurityHeader(soapHeader, securityElement);
	}

	private void appendSecurityHeader(SOAPHeader soapHeader, Element securityElement) {
		soapHeader.removeChild(securityElement);
		soapHeader.appendChild(securityElement);
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
