/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package test.unit.be.e_contract.dssp.client.osgi;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;
import be.e_contract.dssp.client.PendingRequestFactory;
import be.e_contract.dssp.client.SignResponseVerifier;

public class DSSClientBundleActivator implements BundleActivator {

	@Override
	public void start(BundleContext bundleContext) throws Exception {
		System.out.println("start");
		new DigitalSignatureServiceClient("https://test.com");
		Class.forName(PendingRequestFactory.class.getName());
		Class.forName(SignResponseVerifier.class.getName());
	}

	@Override
	public void stop(BundleContext bundleContext) throws Exception {
		System.out.println("stop");
	}
}
