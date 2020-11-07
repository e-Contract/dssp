/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2015-2020 e-Contract.be BV.
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

package test.unit.be.e_contract.dssp.client;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

import javax.xml.parsers.DocumentBuilder;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.impl.Utils;

public class DigitalSignatureServiceSessionTest {

	@Test
	public void testSerialization() throws Exception {
		DocumentBuilder documentBuilder = Utils.createSecureDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element securityTokenElement = document.createElement("helloworld");
		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession("response-id", "securityTokenId",
				new byte[10], securityTokenElement);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
		objectOutputStream.writeObject(session);
	}
}
