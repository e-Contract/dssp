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

/**
 * DSS signature types.
 * 
 * @author Frank Cornelis
 * 
 */
public enum SignatureType {

	/**
	 * eID DSS 1.0.x XAdES-X-L signatures.
	 */
	XADES_X_L("urn:be:e-contract:dssp:signature:xades-x-l", "eID DSS XAdES-X-L"),

	/**
	 * ETSI XAdES Baseline profile signatures.
	 */
	XADES_BASELINE("urn:be:e-contract:dssp:signature:xades-baseline",
			"ETSI XAdES LT-Level"),

	/**
	 * ETSI PAdES Baseline profile signatures.
	 */
	PADES_BASELINE("urn:be:e-contract:dssp:signature:pades-baseline",
			"ETSI PAdES LT-Level");

	private final String uri;

	private final String displayName;

	private SignatureType(String uri, String displayName) {
		this.uri = uri;
		this.displayName = displayName;
	}

	public String getUri() {
		return this.uri;
	}

	public String getDisplayName() {
		return this.displayName;
	}
}
