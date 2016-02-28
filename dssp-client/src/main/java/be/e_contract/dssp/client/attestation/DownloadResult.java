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
package be.e_contract.dssp.client.attestation;

import org.w3c.dom.Element;

/**
 * Data container for download results.
 * 
 * @author Frank Cornelis
 *
 */
public class DownloadResult {

	private final byte[] signedDocument;

	private final Element attestation;

	/**
	 * Main constructor.
	 * 
	 * @param signedDocument
	 *            the signed document.
	 * @param attestation
	 *            the attestation SAML assertion element.
	 */
	public DownloadResult(byte[] signedDocument, Element attestation) {
		this.signedDocument = signedDocument;
		this.attestation = attestation;
	}

	/**
	 * Gives back the signed document.
	 * 
	 * @return the signed document.
	 */
	public byte[] getSignedDocument() {
		return this.signedDocument;
	}

	/**
	 * Gives back the attestation SAML assertion as DOM element.
	 * 
	 * @return the attestation SAML assertion.
	 */
	public Element getAttestation() {
		return this.attestation;
	}
}
