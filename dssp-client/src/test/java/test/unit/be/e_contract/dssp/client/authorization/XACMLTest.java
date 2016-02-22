/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014-2016 e-Contract.be BVBA.
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

import static org.junit.Assert.assertEquals;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.cond.FunctionFactory;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.support.finder.StaticPolicyFinderModule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XACMLTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(XACMLTest.class);

	@Test
	public void testXACML() throws Exception {
		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_PERMIT, responseContext.getDecision());
	}

	@Test
	public void testXACML2() throws Exception {
		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy-2.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_PERMIT, responseContext.getDecision());
	}

	@Test
	public void testXACML3() throws Exception {

		Set<String> targetFunctions = FunctionFactory.getInstance().getTargetFactory().getSupportedFunctions();
		for (String targetFunction : targetFunctions) {
			if (targetFunction.contains("regexp")) {
				LOGGER.debug("target function: {}", targetFunction);
			}
		}

		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy-3.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request-3.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_PERMIT, responseContext.getDecision());
	}

	@Test
	public void testXACML4() throws Exception {
		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy-4.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request-4.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_PERMIT, responseContext.getDecision());
	}

	@Test
	public void testXACML5() throws Exception {
		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy-5.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request-5.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_PERMIT, responseContext.getDecision());
	}

	@Test
	public void testXACML5_2() throws Exception {
		PDPConfig config = new PDPConfig(null, null, null);
		PolicyFinder policyFinder = config.getPolicyFinder();
		Set<PolicyFinderModule> modules = new HashSet<PolicyFinderModule>();
		List<String> policyList = new LinkedList<String>();
		policyList.add(XACMLTest.class.getResource("/xacml/policy-5.xml").toString());
		PolicyFinderModule policyFinderModule = new StaticPolicyFinderModule(policyList);
		modules.add(policyFinderModule);
		policyFinder.setModules(modules);
		PDP pdp = new PDP(config);

		RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
		requestContext.readRequest(XACMLTest.class.getResourceAsStream("/xacml/request-5-2.xml"));
		RequestCtx requestCtx = (RequestCtx) requestContext.get(XACMLConstants.REQUEST_CTX);

		ResponseCtx responseCtx = pdp.evaluate(requestCtx);

		ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
		responseContext.set(XACMLConstants.RESPONSE_CTX, responseCtx);

		LOGGER.debug("decision: {}", responseContext.getDecision());
		assertEquals(XACMLConstants.DECISION_DENY, responseContext.getDecision());
	}

	@Test
	public void testX500Name() throws Exception {
		String dn = "SERIALNUMBER=1234,C=BE";
		X500Principal x500Principal = new X500Principal(dn);
		LOGGER.debug(x500Principal.getName());
	}
}
