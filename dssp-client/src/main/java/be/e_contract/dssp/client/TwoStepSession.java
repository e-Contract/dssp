/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2017 e-Contract.be BVBA.
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

/**
 * Keeps track of the OASIS DSS localsig two-step approach session.
 *
 * @author Frank Cornelis
 *
 */
public class TwoStepSession implements Serializable {

	private static final long serialVersionUID = 1L;

	private final String correlationId;

	private final String digestAlgo;

	private final byte[] digestValue;

	public TwoStepSession(String correlationId, String digestAlgo, byte[] digestValue) {
		this.correlationId = correlationId;
		this.digestAlgo = digestAlgo;
		this.digestValue = digestValue;
	}

	public String getCorrelationId() {
		return this.correlationId;
	}

	public String getDigestAlgo() {
		return this.digestAlgo;
	}

	public byte[] getDigestValue() {
		return this.digestValue;
	}
}
