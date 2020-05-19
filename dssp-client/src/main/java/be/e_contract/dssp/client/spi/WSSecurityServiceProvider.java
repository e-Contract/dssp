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
package be.e_contract.dssp.client.spi;

import java.security.Provider;

/**
 * Service provider interface for the WSS4J based WS-Security functionality.
 * 
 * @author Frank Cornelis
 *
 */
public interface WSSecurityServiceProvider {

	byte[] createPSHA1Key(byte[] secret, byte[] seed, int offset, long length);

	byte[] base64Decode(String encoded) throws Base64DecodingException;

	String base64Encode(byte[] binaryData);

	Provider getXMLDSigProvider();

	WSSecuritySOAPHandler createWSSecuritySOAPHandler();
}
