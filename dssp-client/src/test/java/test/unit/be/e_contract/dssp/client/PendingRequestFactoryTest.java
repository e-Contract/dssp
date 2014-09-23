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

package test.unit.be.e_contract.dssp.client;

import static org.junit.Assert.assertNotNull;

import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.junit.Test;

import be.e_contract.dssp.client.DigitalSignatureServiceSession;
import be.e_contract.dssp.client.PendingRequestFactory;
import be.e_contract.dssp.client.VisibleSignatureConfiguration;
import be.e_contract.dssp.client.VisibleSignatureProfile;

public class PendingRequestFactoryTest {

	private static final Log LOG = LogFactory
			.getLog(PendingRequestFactoryTest.class);

	@Test
	public void testCreatePendingRequest() throws Exception {
		// setup
		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response identifier", "security token identifier",
				"the key".getBytes(), null);
		String destination = "http://return.back/to/here";

		// operate
		String pendingRequest = PendingRequestFactory.createPendingRequest(
				session, destination, "nl");

		// verify
		assertNotNull(pendingRequest);
		LOG.debug("pending request: " + pendingRequest);
		Base64.decode(pendingRequest);
	}

	@Test
	public void testCreatePendingRequestRoleLocation() throws Exception {
		// setup
		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response identifier", "security token identifier",
				"the key".getBytes(), null);
		String destination = "http://return.back/to/here";

		VisibleSignatureConfiguration visibleSignatureConfiguration = new VisibleSignatureConfiguration();
		visibleSignatureConfiguration.setRole("CEO");
		visibleSignatureConfiguration.setLocation("Brussel");

		// operate
		String pendingRequest = PendingRequestFactory.createPendingRequest(
				session, destination, "nl", visibleSignatureConfiguration);

		// verify
		assertNotNull(pendingRequest);
		LOG.debug("pending request: "
				+ new String(Base64.decode(pendingRequest)));
	}

	@Test
	public void testCreatePendingRequestVisibleSignature() throws Exception {
		// setup
		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response identifier", "security token identifier",
				"the key".getBytes(), null);
		String destination = "http://return.back/to/here";

		VisibleSignatureConfiguration visibleSignatureConfiguration = new VisibleSignatureConfiguration();
		visibleSignatureConfiguration.setVisibleSignaturePosition(1, 10, 20,
				VisibleSignatureProfile.eID_PHOTO);

		// operate
		String pendingRequest = PendingRequestFactory.createPendingRequest(
				session, destination, "nl", visibleSignatureConfiguration);

		// verify
		assertNotNull(pendingRequest);
		LOG.debug("pending request: "
				+ new String(Base64.decode(pendingRequest)));
	}

	@Test
	public void testCreatePendingRequestXACML() throws Exception {
		// setup
		DigitalSignatureServiceSession session = new DigitalSignatureServiceSession(
				"response identifier", "security token identifier",
				"the key".getBytes(), null);
		String destination = "http://return.back/to/here";

		Set<String> authorizedSubjects = new HashSet<String>();
		authorizedSubjects.add("CN=Test,C=BE");
		authorizedSubjects.add("CN=Test2");

		// operate
		String pendingRequest = PendingRequestFactory.createPendingRequest(
				session, destination, "nl", null, true, authorizedSubjects);

		// verify
		assertNotNull(pendingRequest);
		LOG.debug(new String(Base64.decode(pendingRequest)));
	}
}
