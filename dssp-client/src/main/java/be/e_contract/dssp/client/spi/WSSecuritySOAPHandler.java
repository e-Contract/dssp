/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2020 e-Contract.be BV.
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.w3c.dom.Element;

import be.e_contract.dssp.client.DigitalSignatureServiceSession;

public interface WSSecuritySOAPHandler extends SOAPHandler<SOAPMessageContext> {

	void setCredentials(PrivateKey privateKey, X509Certificate certificate);

	void setCredentials(String username, String password);

	void setCredentials(Element samlAssertion);

	void setCredentials(Element samlAssertion, PrivateKey privateKey);

	void setSession(DigitalSignatureServiceSession session);
}
