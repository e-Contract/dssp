/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2015 e-Contract.be BVBA.
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

import java.util.Map;

import javax.activation.DataHandler;
import javax.xml.ws.handler.LogicalHandler;
import javax.xml.ws.handler.LogicalMessageContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * JAX-WS logical handler implementation to add and retrieve SOAP attachments.
 * 
 * @author Frank Cornelis
 * 
 */
public class AttachmentsLogicalHandler implements
		LogicalHandler<LogicalMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(AttachmentsLogicalHandler.class);

	private Map<String, DataHandler> inboundAttachments;

	/**
	 * Default constructor.
	 */
	public AttachmentsLogicalHandler() {
	}

	@Override
	public boolean handleMessage(LogicalMessageContext context) {
		Boolean outbound = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (!outbound) {
			this.inboundAttachments = (Map<String, DataHandler>) context
					.get(MessageContext.INBOUND_MESSAGE_ATTACHMENTS);
			LOG.debug("inbound attachments: "
					+ this.inboundAttachments.keySet());
		}
		return true;
	}

	/**
	 * Gives back a map of all inbound SOAP attachments index by content
	 * identifier.
	 * 
	 * @return
	 */
	public Map<String, DataHandler> getInboundAttachments() {
		return this.inboundAttachments;
	}

	@Override
	public boolean handleFault(LogicalMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
	}
}
