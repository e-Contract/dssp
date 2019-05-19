/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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

package be.e_contract.dssp.client.impl;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

	private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

	public static DocumentBuilder createSecureDocumentBuilder() {
		try {
			return _createSecureDocumentBuilder();
		} catch (ParserConfigurationException e) {
			LOGGER.error("parser config error: " + e.getMessage(), e);
			throw new RuntimeException("parser config error");
		}
	}

	private static DocumentBuilder _createSecureDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		documentBuilderFactory.setXIncludeAware(false);
		documentBuilderFactory.setExpandEntityReferences(false);
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		return documentBuilder;
	}
}
