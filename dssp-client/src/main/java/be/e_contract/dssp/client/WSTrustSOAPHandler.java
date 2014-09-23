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

package be.e_contract.dssp.client;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * WS-Trust SOAP handler to capture incoming security tokens.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSTrustSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private Element requestedSecurityToken;

	/**
	 * Gives back the RequestedSecurityToken content (if present).
	 * 
	 * @return
	 */
	public Element getRequestedSecurityToken() {
		return this.requestedSecurityToken;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context)
			throws SOAPException {
		Element bodyElement = context.getMessage().getSOAPBody();

		NodeList nodeList = bodyElement.getElementsByTagNameNS(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"RequestedSecurityToken");
		Element requestedSecurityTokenElement;
		if (nodeList.getLength() > 0) {
			requestedSecurityTokenElement = (Element) nodeList.item(0)
					.getFirstChild();
		} else {
			requestedSecurityTokenElement = null;
		}

		this.requestedSecurityToken = requestedSecurityTokenElement;
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
