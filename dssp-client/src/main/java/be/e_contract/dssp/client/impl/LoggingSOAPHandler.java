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

package be.e_contract.dssp.client.impl;

import java.io.StringWriter;
import java.util.Map;
import java.util.Set;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

/**
 * JAX-WS SOAP handler to provides logging of the SOAP messages using the
 * Commons Logging framework.
 * 
 * @author Frank Cornelis
 * 
 */
public class LoggingSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(LoggingSOAPHandler.class);

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		if (false == LOGGER.isDebugEnabled()) {
			return true;
		}
		logMessage(context);
		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		if (false == LOGGER.isDebugEnabled()) {
			return true;
		}
		logMessage(context);
		return true;
	}

	private void logMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		LOGGER.debug("outbound message: {}", outboundProperty);
		SOAPMessage soapMessage = context.getMessage();
		try {
			LOGGER.debug("SOAP message: {}", toString(soapMessage.getSOAPPart().getEnvelope()));
		} catch (SOAPException ex) {
			LOGGER.error("SOAP error: " + ex.getMessage(), ex);
			return;
		}
		if (false == outboundProperty) {
			Map<String, DataHandler> inboundMessageAttachments = (Map<String, DataHandler>) context
					.get(MessageContext.INBOUND_MESSAGE_ATTACHMENTS);
			Set<String> attachmentContentIds = inboundMessageAttachments.keySet();
			LOGGER.debug("attachment content ids: {}", attachmentContentIds);
		}
	}

	private String toString(Node node) {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException ex) {
			LOGGER.error("transformer config error: " + ex.getMessage(), ex);
			return null;
		}
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		try {
			transformer.transform(new DOMSource(node), result);
		} catch (TransformerException ex) {
			LOGGER.error("transformer error: " + ex.getMessage(), ex);
			return null;
		}
		return stringWriter.toString();
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
