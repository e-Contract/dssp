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

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;

public class CallbackTestHandler implements CallbackHandler {

	private static final Log LOG = LogFactory.getLog(CallbackTestHandler.class);

	public static byte[] tokenKey;

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			LOG.debug("callback type: " + callback.getClass().getName());
			if (callback instanceof WSPasswordCallback) {
				WSPasswordCallback passwordCallback = (WSPasswordCallback) callback;
				LOG.debug("token identifier: "
						+ passwordCallback.getIdentifier());
				passwordCallback.setKey(CallbackTestHandler.tokenKey);
			}
		}
	}
}
