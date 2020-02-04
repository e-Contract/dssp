/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2020 e-Contract.be BV.
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
package be.e_contract.dssp.client.samesite;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.ws.rs.core.HttpHeaders;

public class SameSiteNoneHttpServletResponseWrapper extends HttpServletResponseWrapper {

	private final HttpServletResponse response;

	public SameSiteNoneHttpServletResponseWrapper(HttpServletResponse response) {
		super(response);
		this.response = response;
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		addSameSiteCookieAttribute();
		super.sendRedirect(location);
	}

	@Override
	public void sendError(int sc) throws IOException {
		addSameSiteCookieAttribute();
		super.sendError(sc);
	}

	@Override
	public void sendError(int sc, String msg) throws IOException {
		addSameSiteCookieAttribute();
		super.sendError(sc, msg);
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		addSameSiteCookieAttribute();
		return super.getWriter();
	}

	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		addSameSiteCookieAttribute();
		return super.getOutputStream();
	}

	private void addSameSiteCookieAttribute() {
		Collection<String> headers = this.response.getHeaders(HttpHeaders.SET_COOKIE);
		boolean firstHeader = true;
		for (String header : headers) { // there can be multiple Set-Cookie attributes
			String flags;
			if (header.contains("Secure;")) {
				flags = "SameSite=None";
			} else {
				flags = "Secure; SameSite=None";
			}
			if (firstHeader) {
				this.response.setHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, flags));
				firstHeader = false;
				continue;
			}
			this.response.addHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, flags));
		}
	}
}
