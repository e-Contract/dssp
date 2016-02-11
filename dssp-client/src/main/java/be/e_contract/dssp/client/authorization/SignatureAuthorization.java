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

package be.e_contract.dssp.client.authorization;

import be.e_contract.dssp.ws.jaxb.xacml.policy.PolicyType;

/**
 * Interface for signature authorization XACML policy providers. This allowed
 * the Digital Signature Service to perform Attribute Based Access Control
 * (ABAC).
 *
 * @author Frank Cornelis
 *
 */
public interface SignatureAuthorization {

	/**
	 * Returns an XACML policy structure.
	 *
	 * @return
	 */
	PolicyType getXACMLPolicy();
}
