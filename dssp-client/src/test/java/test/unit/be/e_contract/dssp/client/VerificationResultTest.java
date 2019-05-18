/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2016-2019 e-Contract.be BVBA.
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
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.joda.time.DateTime;
import org.junit.Test;

import be.e_contract.dssp.client.SignatureInfo;
import be.e_contract.dssp.client.VerificationResult;

public class VerificationResultTest {

	@Test
	public void testSerialization() throws Exception {
		// setup
		DateTime renewTimeStampBefore = new DateTime();
		List<SignatureInfo> signatureInfos = new LinkedList<>();
		SignatureInfo signatureInfo = new SignatureInfo("name", null, new Date(), "role", "location");
		signatureInfos.add(signatureInfo);
		VerificationResult verificationResult = new VerificationResult(signatureInfos, renewTimeStampBefore);

		// operate
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
		objectOutputStream.writeObject(verificationResult);
	}
}
