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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.util.ByteArrayDataSource;
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

	private final Map<String, DataHandler> attachments;

	private Map<String, DataHandler> inboundAttachments;

	/**
	 * Default constructor.
	 */
	public AttachmentsLogicalHandler() {
		this.attachments = new HashMap<String, DataHandler>();
	}

	@Override
	public boolean handleMessage(LogicalMessageContext context) {
		Boolean outbound = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outbound) {
			addAttachments(context);
		} else {
			this.attachments.clear();
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

	private void addAttachments(LogicalMessageContext context) {
		// non of these work under CXF JAX-WS runtime (JBoss).
		// https://issues.apache.org/jira/browse/CXF-5095
		// this issue is fixed in CXF 2.6.9
		// JBoss EAP 6.1.0.Alpha1 comes with CXF 2.6.6
		context.put(MessageContext.OUTBOUND_MESSAGE_ATTACHMENTS,
				this.attachments);
	}

	@Override
	public boolean handleFault(LogicalMessageContext context) {
		this.attachments.clear();
		return true;
	}

	@Override
	public void close(MessageContext context) {
		this.attachments.clear();
	}

	/**
	 * Adds a SOAP attachment.
	 * 
	 * @param mimetype
	 *            the mime-type of the attachment.
	 * @param data
	 *            the attachment data.
	 * @return the content identifier.
	 */
	public String addAttachment(String mimetype, byte[] data) {
		String contentId = UUID.randomUUID().toString();
		DataSource dataSource = new ByteArrayDataSource(data, mimetype);
		DataHandler dataHandler = new DataHandler(dataSource);
		this.attachments.put(contentId, dataHandler);
		return contentId;
	}
}
