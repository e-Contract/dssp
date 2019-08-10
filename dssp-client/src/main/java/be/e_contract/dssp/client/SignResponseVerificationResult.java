/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
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
 * Holds the result of the sign response verifier.
 * 
 * @author Frank Cornelis
 *
 */
public class SignResponseVerificationResult {

	private final String signerIdentity;

	private final String keySelector;

	/**
	 * Main constructor.
	 *
	 * @param signerIdentity the optional signer identity.
	 */
	public SignResponseVerificationResult(String signerIdentity) {
		this(signerIdentity, null);
	}

	/**
	 * Main constructor.
	 *
	 * @param signerIdentity the optional signer identity.
	 * @param keySelector    the optional signer key selector identifier.
	 */
	public SignResponseVerificationResult(String signerIdentity, String keySelector) {
		this.signerIdentity = signerIdentity;
		this.keySelector = keySelector;
	}

	/**
	 * Gives back the signer identity.
	 * 
	 * @return
	 */
	public String getSignerIdentity() {
		return this.signerIdentity;
	}

	/**
	 * Gives back the signatory's token key selector identifier;
	 *
	 * @return
	 */
	public String getKeySelector() {
		return this.keySelector;
	}
}
