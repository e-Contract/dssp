/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2016 e-Contract.be BVBA.
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

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JSR105 Key Selector implementation based on the WS-SecureConversation
 * security token.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurityTokenKeySelector extends KeySelector implements KeySelectorResult {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityTokenKeySelector.class);

	private final byte[] tokenKey;

	/**
	 * Main constructor.
	 * 
	 * @param tokenKey
	 *            the security token key.
	 */
	public SecurityTokenKeySelector(byte[] tokenKey) {
		this.tokenKey = tokenKey;
	}

	@Override
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {
		LOGGER.debug("select");
		return this;
	}

	@Override
	public Key getKey() {
		Key key = new SecretKeySpec(this.tokenKey, "HMACSHA1");
		return key;
	}
}
