/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2020 e-Contract.be BV.
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

package be.e_contract.dssp.client.wss4j2;

import java.security.Provider;
import java.util.Base64;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.wss4j.common.derivedKey.P_SHA1;
import org.apache.wss4j.common.ext.WSSecurityException;

import be.e_contract.dssp.client.spi.Base64DecodingException;
import be.e_contract.dssp.client.spi.WSSecuritySOAPHandler;
import be.e_contract.dssp.client.spi.WSSecurityServiceProvider;

public class WSSecurityWSS4J2 implements WSSecurityServiceProvider {

	@Override
	public byte[] createPSHA1Key(byte[] secret, byte[] seed, int offset, long length) {
		P_SHA1 p_SHA1 = new P_SHA1();
		byte[] key;
		try {
			key = p_SHA1.createKey(secret, seed, 0, 256 / 8);
		} catch (WSSecurityException e) {
			throw new RuntimeException("error generating P_SHA1 key");
		}
		return key;
	}

	@Override
	public WSSecuritySOAPHandler createWSSecuritySOAPHandler() {
		return new WSSecuritySOAPHandlerWSS4J2();
	}

	@Override
	public byte[] base64Decode(String encoded) throws Base64DecodingException {
		return Base64.getMimeDecoder().decode(encoded);
	}

	@Override
	public String base64Encode(byte[] binaryData) {
		return Base64.getMimeEncoder().encodeToString(binaryData);
	}

	@Override
	public Provider getXMLDSigProvider() {
		return new XMLDSigRI();
	}
}
