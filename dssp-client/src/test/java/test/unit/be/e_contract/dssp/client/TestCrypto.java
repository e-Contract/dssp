/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCrypto implements Crypto {

	private static final Logger LOGGER = LoggerFactory.getLogger(TestCrypto.class);

	private static X509Certificate certificate;

	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("getBytesFromCertificates");
		return null;
	}

	@Override
	public CertificateFactory getCertificateFactory() throws WSSecurityException {
		LOGGER.debug("getCertificateFactory");
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException {
		LOGGER.debug("getCertificatesFromBytes");
		return null;
	}

	@Override
	public String getCryptoProvider() {
		LOGGER.debug("getCryptoProvider");
		return null;
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		LOGGER.debug("getDefaultX509Identifier");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(X509Certificate certificate, CallbackHandler callbackHandler)
			throws WSSecurityException {
		LOGGER.debug("getPrivateKey(cert, callback)");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(String identifier, String password) throws WSSecurityException {
		LOGGER.debug("getPrivateKey(id, password)");
		return null;
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getSKIBytesFromCert");
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
		LOGGER.debug("getX509Certificates");
		return null;
	}

	@Override
	public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getX509Identifier");
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
		LOGGER.debug("loadCertificate");
		X509Certificate certificate;
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) certificateFactory.generateCertificate(in);
		} catch (Exception e) {
			throw new WSSecurityException(e.getMessage());
		}
		return certificate;
	}

	@Override
	public void setCertificateFactory(String provider, CertificateFactory certFactory) {
		LOGGER.debug("setCertificateFactory");
	}

	@Override
	public void setCryptoProvider(String provider) {
		LOGGER.debug("setCryptoProvider");
	}

	@Override
	public void setDefaultX509Identifier(String identifier) {
		LOGGER.debug("setDefaultX509Identifier");
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("verifyTrust(certs)");
		return false;
	}

	@Override
	public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
		LOGGER.debug("verifyTrust(publicKey)");
		return false;
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation) throws WSSecurityException {
		LOGGER.debug("verifyTrust(certs, enableRevocation)");
		TestCrypto.certificate = certs[0];
		return true;
	}

	public static X509Certificate getCertificate() {
		return TestCrypto.certificate;
	}
}
