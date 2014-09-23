/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014-2014 e-Contract.be BVBA.
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
 * Thrown in case the user was not authorized to perform the signing operation.
 * 
 * @author Frank Cornelis
 * 
 */
public class SubjectNotAuthorizedException extends Exception {

	private static final long serialVersionUID = 1L;

	private final String signerIdentity;

	/**
	 * Main constructor.
	 * 
	 * @param signerIdentity
	 *            the optional signer identity.
	 */
	public SubjectNotAuthorizedException(String signerIdentity) {
		this.signerIdentity = signerIdentity;
	}

	/**
	 * Gives back the identity of the entity that tried to sign the document.
	 * 
	 * @return
	 */
	public String getSignerIdentity() {
		return this.signerIdentity;
	}
}
