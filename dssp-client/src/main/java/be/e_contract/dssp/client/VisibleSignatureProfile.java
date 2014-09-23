/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;

/**
 * Enumerates the different signature visualization flavors.
 * 
 * @author Frank Cornelis
 *
 */
public enum VisibleSignatureProfile {

	eID_PHOTO(DigitalSignatureServiceConstants.VISIBLE_SIGNATURE_SIGNER_IMAGE_EID_PHOTO);

	private final String signerImageUri;

	private VisibleSignatureProfile(String signerImageUri) {
		this.signerImageUri = signerImageUri;
	}

	public String getSignerImageUri() {
		return this.signerImageUri;
	}
}
