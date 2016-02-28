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
package be.e_contract.dssp.client.impl;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * JAX-WS SOAP handler to retrieve the attestation SAML assertion from the DSS
 * response message.
 * 
 * @author Frank Cornelis
 *
 */
public class AttestationSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(AttestationSOAPHandler.class);

	private Element attestation;

	@Override
	public Set<QName> getHeaders() {
		return null;
	}

	public Element getAttestation() {
		return this.attestation;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outboundProperty) {
			return true;
		}
		try {
			handleInboundMessage(context);
		} catch (Exception e) {
			LOGGER.error("error: " + e.getMessage(), e);
			throw new ProtocolException(e);
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context) throws Exception {
		NodeList attestationResponseNodeList = context.getMessage().getSOAPBody()
				.getElementsByTagNameNS("urn:be:e-contract:dssp:1.0", "AttestationResponse");
		if (attestationResponseNodeList.getLength() == 0) {
			this.attestation = null;
			return;
		}
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element importedElement = (Element) document.importNode(attestationResponseNodeList.item(0).getFirstChild(),
				true);
		document.appendChild(importedElement);
		this.attestation = importedElement;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
		// empty
	}
}
