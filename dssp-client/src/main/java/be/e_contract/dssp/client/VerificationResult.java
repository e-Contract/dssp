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

import java.util.List;

import org.joda.time.DateTime;

/**
 * Holds signature verification results.
 * 
 * @author Frank Cornelis
 * 
 */
public class VerificationResult {

	private final DateTime renewTimeStampBefore;

	private final List<SignatureInfo> signatureInfos;

	/**
	 * Main constructor.
	 * 
	 * @param signatureInfos
	 * @param renewTimeStampBefore
	 */
	public VerificationResult(List<SignatureInfo> signatureInfos,
			DateTime renewTimeStampBefore) {
		this.signatureInfos = signatureInfos;
		this.renewTimeStampBefore = renewTimeStampBefore;
	}

	/**
	 * Gives back the date before which the document should receive a new time
	 * stamp for long-term signature validity.
	 * 
	 * @return
	 */
	public DateTime getRenewTimeStampBefore() {
		return this.renewTimeStampBefore;
	}

	/**
	 * Gives back a list of signature information.
	 * 
	 * @return
	 */
	public List<SignatureInfo> getSignatureInfos() {
		return this.signatureInfos;
	}
}
