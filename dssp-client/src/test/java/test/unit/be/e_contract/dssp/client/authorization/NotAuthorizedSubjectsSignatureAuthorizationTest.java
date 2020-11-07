/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2016-2020 e-Contract.be BV.
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

package test.unit.be.e_contract.dssp.client.authorization;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.StringWriter;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.dssp.client.authorization.NotAuthorizedSubjectsSignatureAuthorization;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.xacml.policy.PolicyType;

public class NotAuthorizedSubjectsSignatureAuthorizationTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(NotAuthorizedSubjectsSignatureAuthorizationTest.class);

	@Test
	public void testPolicy() throws Exception {
		// setup
		Set<String> authorizedSubjects = new HashSet<String>();
		authorizedSubjects.add("CN=NotAuthorizedSubject");
		NotAuthorizedSubjectsSignatureAuthorization signatureAuthorization = new NotAuthorizedSubjectsSignatureAuthorization(
				authorizedSubjects);

		// operate
		PolicyType policy = signatureAuthorization.getXACMLPolicy();

		// verify
		assertNotNull(policy);
		LOGGER.debug("policy: {}", toString(policy));
	}

	private String toString(PolicyType policy) throws Exception {
		ObjectFactory objectFactory = new ObjectFactory();
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		Marshaller marshaller = jaxbContext.createMarshaller();
		StringWriter stringWriter = new StringWriter();
		marshaller.marshal(objectFactory.createPolicy(policy), stringWriter);
		return stringWriter.toString();
	}
}
