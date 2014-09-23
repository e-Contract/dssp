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

import java.io.Serializable;

import org.w3c.dom.Element;

/**
 * Session object for DSSP. Is serializable to be able to get stored inside an
 * HTTP session context.
 * 
 * @author Frank Cornelis
 * 
 */
public class DigitalSignatureServiceSession implements Serializable {

	private static final long serialVersionUID = 1L;

	private final String responseId;

	private final String securityTokenId;

	private byte[] key;

	private final Element securityTokenElement;

	private String destination;

	private String inResponseTo;

	private boolean signResponseVerified;

	public DigitalSignatureServiceSession(String responseId,
			String securityTokenId, byte[] key, Element securityTokenElement) {
		this.responseId = responseId;
		this.securityTokenId = securityTokenId;
		this.key = key;
		this.securityTokenElement = securityTokenElement;
	}

	/**
	 * Gives back the OASIS DSS Async ResponseID value.
	 * 
	 * @return
	 */
	public String getResponseId() {
		return this.responseId;
	}

	/**
	 * Gives back the WS-SecureConversation security token identifier.
	 * 
	 * @return
	 */
	public String getSecurityTokenId() {
		return this.securityTokenId;
	}

	/**
	 * Gives back the WS-SecureConversation proof-of-possession session key.
	 * 
	 * @return
	 */
	public byte[] getKey() {
		return this.key;
	}

	/**
	 * Gives back the WS-SecureConversation security token as DOM element.
	 * 
	 * @return
	 */
	public Element getSecurityTokenElement() {
		return this.securityTokenElement;
	}

	public void setDestination(String destination) {
		this.destination = destination;
	}

	public String getDestination() {
		return this.destination;
	}

	public void setInResponseTo(String inResponseTo) {
		this.inResponseTo = inResponseTo;
	}

	public String getInResponseTo() {
		return this.inResponseTo;
	}

	public void setSignResponseVerified(boolean signResponseVerified) {
		this.signResponseVerified = signResponseVerified;
	}

	public boolean isSignResponseVerified() {
		return this.signResponseVerified;
	}
}
