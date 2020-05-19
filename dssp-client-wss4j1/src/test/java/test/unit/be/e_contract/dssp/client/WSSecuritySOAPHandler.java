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

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WSSecuritySOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSSecuritySOAPHandler.class);

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty.booleanValue()) {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context) throws WSSecurityException, SOAPException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecurityEngine secEngine = new WSSecurityEngine();
		WSSConfig wssConfig = new WSSConfig();
		secEngine.setWssConfig(wssConfig);
		CallbackHandler callbackHandler = new CallbackTestHandler();
		Crypto crypto = new TestCrypto();
		List<WSSecurityEngineResult> results = secEngine.processSecurityHeader(soapPart, null, callbackHandler, crypto);
		if (null == results) {
			LOGGER.debug("no WS-Security results");
			return;
		}
		for (WSSecurityEngineResult result : results) {
			LOGGER.debug("result key set: {}", result.keySet());
		}
		LOGGER.debug("SAML token signed {}", WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED) != null);
		LOGGER.debug("SAML token unsigned {}",
				WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED) != null);

		WSSecurityEngineResult samlTokenSignedResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
		if (null != samlTokenSignedResult) {
			// see CXF SamlTokenInterceptor
			AssertionWrapper assertionWrapper = (AssertionWrapper) samlTokenSignedResult
					.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
			List<String> confirmationMethods = assertionWrapper.getConfirmationMethods();
			if (isHolderOfKey(confirmationMethods)) {
				LOGGER.debug("holder-of-key SAML detected");
				WSSecurityEngineResult signResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
				if (null == signResult) {
					throw new SecurityException("holder-of-key requires ds:Signature");
				}
				SAMLKeyInfo subjectKeyInfo = assertionWrapper.getSubjectKeyInfo();
				PublicKey subjectPublicKey = subjectKeyInfo.getPublicKey();
				PublicKey publicKey = (PublicKey) signResult.get(WSSecurityEngineResult.TAG_PUBLIC_KEY);
				if (!subjectPublicKey.equals(publicKey)) {
					throw new SecurityException("WS-Security ds:Signature key != SAML holder-of-key key");
				}
				LOGGER.debug("holder-of-key signature present");
			}
		}
	}

	private boolean isHolderOfKey(List<String> confirmationMethods) {
		for (String confirmationMethod : confirmationMethods) {
			if (confirmationMethod != null && confirmationMethod.startsWith("urn:oasis:names:tc:SAML:")
					&& confirmationMethod.endsWith(":cm:holder-of-key")) {
				return true;
			}
		}
		return false;
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
		return Collections.singleton(new QName(
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security"));
	}
}
