/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2017 e-Contract.be BVBA.
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

package be.e_contract.dssp.ws;

import javax.xml.namespace.QName;

public class DigitalSignatureServiceConstants {

	public static final String PROFILE = "urn:be:e-contract:dssp:1.0";

	public static final String ESEAL_PROFILE = "urn:be:e-contract:dssp:eseal:1.0";

	public static final String LOCALSIG_PROFILE = "http://docs.oasis-open.org/dss-x/ns/localsig";

	public static final String TWO_STEP_APPROACH_SERVICE_POLICY = "http://docs.oasis-open.org/dss-x/ns/localsig/two-step-approach";

	public static final String WS_SEC_CONV_TOKEN_TYPE = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct";

	public static final String WS_TRUST_ISSUE_REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";

	public static final String WS_TRUST_CANCEL_REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";

	public static final String WS_TRUST_BINARY_SECRET_NONCE_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";

	public static final String DSS_ASYNC_PROFILE = "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing";

	public static final String SHA1_DIGEST_METHOD_TYPE = "http://www.w3.org/2000/09/xmldsig#sha1";

	public static final String SUCCESS_RESULT_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

	public static final String VR_RESULT_MAJOR_VALID = "urn:oasis:names:tc:dss:1.0:detail:valid";

	public static final String PENDING_RESULT_MAJOR = "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending";

	public static final String PSHA1_COMPUTED_KEY = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";

	public static final String REQUESTER_ERROR_RESULT_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

	public static final String RESPONDER_ERROR_RESULT_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError";

	public static final String UNSUPPORTED_MIME_TYPE_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:UnsupportedMimeType";

	public static final String UNSUPPORTED_SIGNATURE_TYPE_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:UnsupportedSignatureType";

	public static final String INCORRECT_SIGNATURE_TYPE_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:IncorrectSignatureType";

	public static final String INSUFFICIENT_INFO_RESULT_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation";

	public static final String INCORRECT_SIGNATURE_RESULT_MINOR = "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature";

	public static final String USER_CANCEL_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:user-cancelled";

	public static final String CLIENT_RUNTIME_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:client-runtime";

	public static final String AUTHENTICATION_REQUIRED_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:authentication-required";

	public static final String SUBJECT_NOT_AUTHORIZED_RESULT_MINOR = "urn:be:e-contract:dssp:1.0:resultminor:subject-not-authorized";

	public static final String KEY_LOOKUP_FAILED_RESULT_MINOR = "urn:oasis:names:tc:dss:1.0:resultminor:invalid:KeyLookupFailed";

	public static final String KEY_INFO_NOT_PROVIDED_RESULT_MINOR = "urn:oasis:names:tc:dss:1.0:resultminor:KeyInfoNotProvided";

	public static final String DOCUMENT_HASH_RESULT_MINOR = "urn:oasis:names:tc:dss:1.0:resultminor:documentHash";

	public static final String VISIBLE_SIGNATURE_SIGNER_IMAGE_EID_PHOTO = "urn:be:e-contract:dssp:1.0:vs:si:eid-photo";

	public static final String VISIBLE_SIGNATURE_SIGNER_IMAGE_EID_PHOTO_SIGNER_INFO = "urn:be:e-contract:dssp:1.0:vs:si:eid-photo:signer-info";

	public static final String DOCUMENT_AUTHORIZATION_RESOURCE_SHA256_URI = "urn:be:e-contract:dssp:document:digest:sha-256:";

	public static final String DOCUMENT_AUTHORIZATION_ACTION_NAMESPACE = "urn:be:e-contract:dssp";

	public static final String DOCUMENT_AUTHORIZATION_ACTION_ACTION_SIGN = "sign";

	public static final String DOCUMENT_DIGEST_ATTESTATION_SAML_ATTRIBUTE_NAME = "urn:be:e-contract:dssp:attestation:document:digest:sha-256";

	public static final String SIGNED_DOCUMENT_DIGEST_ATTESTATION_SAML_ATTRIBUTE_NAME = "urn:be:e-contract:dssp:attestation:signed-document:digest:sha-256";

	public static final String REF_DOC_NOT_PRESENT_RESULT_MINOR = "urn:oasis:names:tc:dss:1.0:resultminor:ReferencedDocumentNotPresent";

	public static final QName ASYNC_RESPONSEID_QNAME = new QName(
			"urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0", "ResponseID");

	public static final QName CORRELATION_ID_QNAME = new QName("http://docs.oasis-open.org/dss-x/ns/localsig",
			"CorrelationID");

	private DigitalSignatureServiceConstants() {
		super();
	}
}
