/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2017-2021 e-Contract.be BV.
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

package be.e_contract.dssp.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keeps track of the OASIS DSS localsig two-step approach session.
 *
 * @author Frank Cornelis
 *
 */
public class TwoStepSession implements Serializable {

	private static final Logger LOGGER = LoggerFactory.getLogger(TwoStepSession.class);

	private static final long serialVersionUID = 1L;

	private static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
			0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

	private static final byte[] SHA224_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
			(byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c };

	private static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
			(byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

	private static final byte[] SHA384_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
			(byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

	private static final byte[] SHA512_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
			(byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

	private static final Map<String, byte[]> digestInfoPrefixes;

	static {
		digestInfoPrefixes = new HashMap<>();
		digestInfoPrefixes.put("SHA-1", SHA1_DIGEST_INFO_PREFIX);
		digestInfoPrefixes.put("SHA-224", SHA224_DIGEST_INFO_PREFIX);
		digestInfoPrefixes.put("SHA-256", SHA256_DIGEST_INFO_PREFIX);
		digestInfoPrefixes.put("SHA-384", SHA384_DIGEST_INFO_PREFIX);
		digestInfoPrefixes.put("SHA-512", SHA512_DIGEST_INFO_PREFIX);
	}

	private final String correlationId;

	private final String digestAlgo;

	private final byte[] digestValue;

	/**
	 * Main constructor.
	 * 
	 * @param correlationId
	 * @param digestAlgo
	 * @param digestValue
	 */
	public TwoStepSession(String correlationId, String digestAlgo, byte[] digestValue) {
		this.correlationId = correlationId;
		this.digestAlgo = digestAlgo;
		this.digestValue = digestValue;
	}

	public String getCorrelationId() {
		return this.correlationId;
	}

	public String getDigestAlgo() {
		return this.digestAlgo;
	}

	public byte[] getDigestValue() {
		return this.digestValue;
	}

	/**
	 * Signs the received digest value using an RSA key.
	 * 
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public byte[] sign(PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		if (null == this.digestAlgo) {
			throw new IllegalStateException();
		}
		if (null == this.digestValue) {
			throw new IllegalStateException();
		}
		LOGGER.debug("digest algo: {}", this.digestAlgo);
		String signatureAlgorithm;
		if (privateKey.getAlgorithm().equals("EC")) {
			signatureAlgorithm = "NONEwithECDSA";
		} else {
			signatureAlgorithm = "NONEwithRSA";
		}
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initSign(privateKey);

		ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
		if (privateKey.getAlgorithm().equals("RSA")) {
			byte[] digestInfoPrefix = digestInfoPrefixes.get(this.digestAlgo);
			if (null == digestInfoPrefix) {
				throw new NoSuchAlgorithmException(this.digestAlgo);
			}
			digestInfo.write(digestInfoPrefix);
		}
		digestInfo.write(this.digestValue);

		signature.update(digestInfo.toByteArray());

		byte[] signatureValue = signature.sign();
		return signatureValue;
	}
}
