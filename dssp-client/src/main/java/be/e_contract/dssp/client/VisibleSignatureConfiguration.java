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
 * Visible Signature Configuration.
 * 
 * @author Frank Cornelis
 * 
 */
public class VisibleSignatureConfiguration {

	public String role;

	public String location;

	public Integer page;

	public Integer x;

	public Integer y;

	public VisibleSignatureProfile profile;

	/**
	 * Sets the position of the visible signature.
	 * 
	 * @param page
	 *            the page.
	 * @param x
	 *            the x position on the page.
	 * @param y
	 *            the y position on the page.
	 * @param profile
	 *            the visualization profile.
	 * @see {@link VisibleSignatureProfile}
	 */
	public void setVisibleSignaturePosition(int page, int x, int y,
			VisibleSignatureProfile profile) {
		this.page = page;
		this.x = x;
		this.y = y;
		this.profile = profile;
	}

	public String getRole() {
		return this.role;
	}

	/**
	 * Sets the role to be used during signature creation. For PAdES this
	 * translates to the Reason field. For XAdES this translates to a
	 * ClaimedRole element.
	 * 
	 * @param role
	 */
	public void setRole(String role) {
		this.role = role;
	}

	public String getLocation() {
		return this.location;
	}

	/**
	 * Sets the location to be used during signature creation. For PAdES this
	 * translates to the Location field. For XAdES this translates to a
	 * SignatureProductionPlace/City element.
	 * 
	 * @param location
	 */
	public void setLocation(String location) {
		this.location = location;
	}

	public Integer getPage() {
		return this.page;
	}

	public Integer getX() {
		return this.x;
	}

	public Integer getY() {
		return this.y;
	}

	public VisibleSignatureProfile getProfile() {
		return this.profile;
	}
}
