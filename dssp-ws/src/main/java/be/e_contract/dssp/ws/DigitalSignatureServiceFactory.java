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

package be.e_contract.dssp.ws;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.dssp.ws.jaxws.DigitalSignatureService;

public class DigitalSignatureServiceFactory {

	private DigitalSignatureServiceFactory() {
		super();
	}

	public static DigitalSignatureService newInstance() {
		URL wsdlLocation = DigitalSignatureServiceFactory.class
				.getResource("/dssp-ws.wsdl");
		QName serviceName = new QName("urn:be:e_contract:dssp:ws",
				"DigitalSignatureService");
		DigitalSignatureService digitalSignatureService = new DigitalSignatureService(
				wsdlLocation, serviceName);
		return digitalSignatureService;
	}
}
