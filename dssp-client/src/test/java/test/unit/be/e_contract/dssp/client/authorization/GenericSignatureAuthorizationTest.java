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

package test.unit.be.e_contract.dssp.client.authorization;

import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.dssp.client.authorization.GenericSignatureAuthorization;
import be.e_contract.dssp.ws.jaxb.xacml.policy.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.xacml.policy.PolicyType;

public class GenericSignatureAuthorizationTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(GenericSignatureAuthorizationTest.class);

	@Test
	public void testAuthorizedSubject() throws Exception {
		// setup
		GenericSignatureAuthorization authorization = new GenericSignatureAuthorization();
		authorization.addAuthorizedSubjectName("CN=Authorized");

		// operate
		PolicyType policy = authorization.getXACMLPolicy();

		// verify
		LOGGER.debug("XACML policy: {}", toString(policy));
	}

	@Test
	public void testNotAuthorizedSubject() throws Exception {
		// setup
		GenericSignatureAuthorization authorization = new GenericSignatureAuthorization();
		authorization.addNonAuthorizedSubjectName("CN=NotAuthorized");

		// operate
		PolicyType policy = authorization.getXACMLPolicy();

		// verify
		LOGGER.debug("XACML policy: {}", toString(policy));
	}

	@Test
	public void testAuthorizedCardNumber() throws Exception {
		// setup
		GenericSignatureAuthorization authorization = new GenericSignatureAuthorization();
		authorization.addAuthorizedCardNumber("12345678");

		// operate
		PolicyType policy = authorization.getXACMLPolicy();

		// verify
		LOGGER.debug("XACML policy: {}", toString(policy));
	}

	@Test
	public void testNotAuthorizedCardNumber() throws Exception {
		// setup
		GenericSignatureAuthorization authorization = new GenericSignatureAuthorization();
		authorization.addNonAuthorizedCardNumber("12345678");

		// operate
		PolicyType policy = authorization.getXACMLPolicy();

		// verify
		LOGGER.debug("XACML policy: {}", toString(policy));
	}

	private String toString(PolicyType policy) throws Exception {
		ObjectFactory objectFactory = new ObjectFactory();
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
		StringWriter stringWriter = new StringWriter();
		marshaller.marshal(objectFactory.createPolicy(policy), stringWriter);
		return stringWriter.toString();
	}
}
