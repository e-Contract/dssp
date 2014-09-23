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

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Structure that holds information about a signature.
 * 
 * @author Frank Cornelis
 * 
 */
public class SignatureInfo {

	private final String name;

	private final X509Certificate certificate;

	private final Date signingTime;

	private final String role;

	private final String location;

	/**
	 * Main constructor.
	 * 
	 * @param name
	 *            the name of the signer.
	 * @param certificate
	 *            the X509 certificate of the signer.
	 * @param signingTime
	 *            the claimed signing time of the signature.
	 * @param role
	 *            the signatory's role.
	 * @param location
	 *            the signing location.
	 */
	public SignatureInfo(String name, X509Certificate certificate,
			Date signingTime, String role, String location) {
		this.name = name;
		this.certificate = certificate;
		this.signingTime = signingTime;
		this.role = role;
		this.location = location;
	}

	/**
	 * Gives back the name of the signer.
	 * 
	 * @return
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Gives back the X509 certificate of the signer.
	 * 
	 * @return
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	/**
	 * Gives back the claimed signing time of the signature.
	 * 
	 * @return
	 */
	public Date getSigningTime() {
		return this.signingTime;
	}

	/**
	 * Gives back the signatory's role.
	 * 
	 * @return
	 */
	public String getRole() {
		return this.role;
	}

	/**
	 * Gives back the signing location.
	 * 
	 * @return
	 */
	public String getLocation() {
		return this.location;
	}
}