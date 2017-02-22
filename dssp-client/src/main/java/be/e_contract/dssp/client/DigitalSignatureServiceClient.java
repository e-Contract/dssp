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
package be.e_contract.dssp.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.util.ByteArrayDataSource;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.io.IOUtils;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.P_SHA1;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import be.e_contract.dssp.client.attestation.DownloadResult;
import be.e_contract.dssp.client.exception.ApplicationDocumentAuthorizedException;
import be.e_contract.dssp.client.exception.AuthenticationRequiredException;
import be.e_contract.dssp.client.exception.DocumentSignatureException;
import be.e_contract.dssp.client.exception.IncorrectSignatureTypeException;
import be.e_contract.dssp.client.exception.KeyInfoNotProvidedException;
import be.e_contract.dssp.client.exception.KeyLookupException;
import be.e_contract.dssp.client.exception.UnsupportedDocumentTypeException;
import be.e_contract.dssp.client.exception.UnsupportedSignatureTypeException;
import be.e_contract.dssp.client.impl.AttachmentsLogicalHandler;
import be.e_contract.dssp.client.impl.AttestationSOAPHandler;
import be.e_contract.dssp.client.impl.WSSecuritySOAPHandler;
import be.e_contract.dssp.client.impl.WSTrustSOAPHandler;
import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.DigitalSignatureServiceFactory;
import be.e_contract.dssp.ws.jaxb.dss.AdditionalKeyInfo;
import be.e_contract.dssp.ws.jaxb.dss.AnyType;
import be.e_contract.dssp.ws.jaxb.dss.AttachmentReferenceType;
import be.e_contract.dssp.ws.jaxb.dss.Base64Data;
import be.e_contract.dssp.ws.jaxb.dss.Base64Signature;
import be.e_contract.dssp.ws.jaxb.dss.DocumentHash;
import be.e_contract.dssp.ws.jaxb.dss.DocumentType;
import be.e_contract.dssp.ws.jaxb.dss.DocumentWithSignature;
import be.e_contract.dssp.ws.jaxb.dss.InputDocuments;
import be.e_contract.dssp.ws.jaxb.dss.KeySelector;
import be.e_contract.dssp.ws.jaxb.dss.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.dss.ResponseBaseType;
import be.e_contract.dssp.ws.jaxb.dss.Result;
import be.e_contract.dssp.ws.jaxb.dss.SignRequest;
import be.e_contract.dssp.ws.jaxb.dss.SignResponse;
import be.e_contract.dssp.ws.jaxb.dss.SignatureObject;
import be.e_contract.dssp.ws.jaxb.dss.SignaturePlacement;
import be.e_contract.dssp.ws.jaxb.dss.VerifyRequest;
import be.e_contract.dssp.ws.jaxb.dss.async.PendingRequest;
import be.e_contract.dssp.ws.jaxb.dss.vr.CertificateValidityType;
import be.e_contract.dssp.ws.jaxb.dss.vr.DetailedSignatureReportType;
import be.e_contract.dssp.ws.jaxb.dss.vr.IndividualReportType;
import be.e_contract.dssp.ws.jaxb.dss.vr.ReturnVerificationReport;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignedObjectIdentifierType;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignerRoleType;
import be.e_contract.dssp.ws.jaxb.dss.vr.VerificationReportType;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemNameEnum;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemValueStringType;
import be.e_contract.dssp.ws.jaxb.dss.vs.ItemValueURIType;
import be.e_contract.dssp.ws.jaxb.dss.vs.PixelVisibleSignaturePositionType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureConfigurationType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureItemType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignatureItemsConfigurationType;
import be.e_contract.dssp.ws.jaxb.dss.vs.VisibleSignaturePolicyType;
import be.e_contract.dssp.ws.jaxb.dssp.AttestationRequestType;
import be.e_contract.dssp.ws.jaxb.dssp.DeadlineType;
import be.e_contract.dssp.ws.jaxb.localsig.ReturnDocumentHash;
import be.e_contract.dssp.ws.jaxb.wssc.SecurityContextTokenType;
import be.e_contract.dssp.ws.jaxb.wsse.ReferenceType;
import be.e_contract.dssp.ws.jaxb.wsse.SecurityTokenReferenceType;
import be.e_contract.dssp.ws.jaxb.wst.BinarySecretType;
import be.e_contract.dssp.ws.jaxb.wst.CancelTargetType;
import be.e_contract.dssp.ws.jaxb.wst.EntropyType;
import be.e_contract.dssp.ws.jaxb.wst.RequestSecurityTokenResponseCollectionType;
import be.e_contract.dssp.ws.jaxb.wst.RequestSecurityTokenResponseType;
import be.e_contract.dssp.ws.jaxb.wst.RequestSecurityTokenType;
import be.e_contract.dssp.ws.jaxb.wst.RequestedSecurityTokenType;
import be.e_contract.dssp.ws.jaxb.xades.ClaimedRolesListType;
import be.e_contract.dssp.ws.jaxb.xmldsig.DigestMethodType;
import be.e_contract.dssp.ws.jaxb.xmldsig.KeyInfoType;
import be.e_contract.dssp.ws.jaxb.xmldsig.X509DataType;
import be.e_contract.dssp.ws.jaxws.DigitalSignatureService;
import be.e_contract.dssp.ws.jaxws.DigitalSignatureServicePortType;

/**
 * Client for eID DSS products that support the Digital Signature Service
 * Protocol. Note that this client is not thread-safe.
 *
 * @author Frank Cornelis
 *
 */
public class DigitalSignatureServiceClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(DigitalSignatureServiceClient.class);

	private final DigitalSignatureServicePortType dssPort;

	private final ObjectFactory objectFactory;

	private final be.e_contract.dssp.ws.jaxb.wst.ObjectFactory wstObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory dsObjectFactory;

	private final SecureRandom secureRandom;

	private final AttachmentsLogicalHandler attachmentsSOAPHandler;

	private final be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory asyncObjectFactory;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final WSTrustSOAPHandler wsTrustSOAPHandler;

	private final AttestationSOAPHandler attestationSOAPHandler;

	private final be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory wsseObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory vrObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory dsspObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory vsObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.localsig.ObjectFactory localsigObjectFactory;

	private final CertificateFactory certificateFactory;

	private String username;

	private String password;

	private PrivateKey privateKey;

	private X509Certificate certificate;

	private Element samlAssertion;

	private final static Map<String, String> digestAlgoToDigestMethod;

	static {
		digestAlgoToDigestMethod = new HashMap<String, String>();
		digestAlgoToDigestMethod.put("SHA1", "http://www.w3.org/2000/09/xmldsig#sha1");
		digestAlgoToDigestMethod.put("SHA-1", "http://www.w3.org/2000/09/xmldsig#sha1");
		digestAlgoToDigestMethod.put("SHA-224", "http://www.w3.org/2001/04/xmldsig-more#sha224");
		digestAlgoToDigestMethod.put("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256");
		digestAlgoToDigestMethod.put("SHA-384", "http://www.w3.org/2001/04/xmldsig-more#sha384");
		digestAlgoToDigestMethod.put("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512");
	}

	/**
	 * Main constructor.
	 *
	 * @param address
	 *            the location of the DSSP web service.
	 */
	public DigitalSignatureServiceClient(String address) {
		DigitalSignatureService digitalSignatureService = DigitalSignatureServiceFactory.newInstance();
		this.dssPort = digitalSignatureService.getDigitalSignatureServicePort();

		BindingProvider bindingProvider = (BindingProvider) this.dssPort;
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, address);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		this.attachmentsSOAPHandler = new AttachmentsLogicalHandler();
		handlerChain.add(this.attachmentsSOAPHandler);
		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		handlerChain.add(this.wsSecuritySOAPHandler);
		this.wsTrustSOAPHandler = new WSTrustSOAPHandler();
		handlerChain.add(this.wsTrustSOAPHandler);
		this.attestationSOAPHandler = new AttestationSOAPHandler();
		handlerChain.add(this.attestationSOAPHandler);
		// cannot add LoggingSOAPHandler here, else we break SOAP with
		// attachments on Apache CXF
		// handlerChain.add(new LoggingSOAPHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.wstObjectFactory = new be.e_contract.dssp.ws.jaxb.wst.ObjectFactory();
		this.dsObjectFactory = new be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory();
		this.asyncObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory();
		this.wsseObjectFactory = new be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory();
		this.vrObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory();
		this.dsspObjectFactory = new be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory();
		this.vsObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vs.ObjectFactory();
		this.localsigObjectFactory = new be.e_contract.dssp.ws.jaxb.localsig.ObjectFactory();

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());

		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	private void resetCredentials() {
		this.username = null;
		this.password = null;
		this.privateKey = null;
		this.certificate = null;
		this.samlAssertion = null;
	}

	/**
	 * Sets the username/password credentials to be used during the document
	 * uploading.
	 *
	 * @param username
	 *            your application username.
	 * @param password
	 *            your application password.
	 */
	public void setCredentials(String username, String password) {
		resetCredentials();
		this.username = username;
		this.password = password;
	}

	/**
	 * Sets the X509 credentials to be used during the document uploading.
	 *
	 * @param privateKey
	 *            the application private key.
	 * @param certificate
	 *            the application X509 certificate.
	 */
	public void setCredentials(PrivateKey privateKey, X509Certificate certificate) {
		resetCredentials();
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	/**
	 * Sets the bearer SAML 2.0 assertion credentials to be used during the
	 * document uploading.
	 *
	 * @param samlAssertion
	 */
	public void setCredentials(Element samlAssertion) {
		resetCredentials();
		this.samlAssertion = samlAssertion;
	}

	/**
	 * Sets the holder-of-key SAML 2.0 assertion credentials to be used during
	 * the document uploading.
	 *
	 * @param samlAssertion
	 * @param privateKey
	 *            the proof-of-possession private key.
	 */
	public void setCredentials(Element samlAssertion, PrivateKey privateKey) {
		resetCredentials();
		this.samlAssertion = samlAssertion;
		this.privateKey = privateKey;
	}

	/**
	 * Uploads a given document to the DSS in preparation of a signing ceremony.
	 *
	 * @param mimetype
	 * @param signatureType
	 *            the optional signature type. If none is provided, the DSS will
	 *            select the most appropriate.
	 * @param data
	 * @return
	 * @throws UnsupportedDocumentTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws AuthenticationRequiredException
	 * @throws ApplicationDocumentAuthorizedException
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, SignatureType signatureType, byte[] data)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, ApplicationDocumentAuthorizedException {
		return uploadDocument(mimetype, signatureType, data, false);
	}

	/**
	 * Uploads a given document to the DSS in preparation of a signing ceremony.
	 *
	 * @param mimetype
	 * @param data
	 * @return
	 * @throws UnsupportedDocumentTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws AuthenticationRequiredException
	 * @throws ApplicationDocumentAuthorizedException
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, byte[] data)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, ApplicationDocumentAuthorizedException {
		return uploadDocument(mimetype, null, data, false);
	}

	/**
	 * Uploads a given document to the DSS in preparation of a signing ceremony.
	 *
	 * @param mimetype
	 *            the mime-type of the document.
	 * @param signatureType
	 *            the optional signature type. If none is provided, the DSS will
	 *            select the most appropriate.
	 * @param data
	 *            the data bytes of the document.
	 * @param useAttachments
	 *            set to <code>true</code> to use SOAP attachments.
	 * @return a session object. Should be saved within the HTTP session for
	 *         later usage.
	 * @throws UnsupportedDocumentTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws AuthenticationRequiredException
	 * @throws ApplicationDocumentAuthorizedException
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, SignatureType signatureType, byte[] data,
			boolean useAttachments) throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException,
			IncorrectSignatureTypeException, AuthenticationRequiredException, ApplicationDocumentAuthorizedException {
		return uploadDocument(mimetype, signatureType, data, useAttachments, false);
	}

	private void configureCredentials() {
		if (null != this.username) {
			this.wsSecuritySOAPHandler.setCredentials(this.username, this.password);
		}
		if (null != this.privateKey) {
			this.wsSecuritySOAPHandler.setCredentials(this.privateKey, this.certificate);
		}
		if (null != this.samlAssertion) {
			if (this.privateKey == null) {
				this.wsSecuritySOAPHandler.setCredentials(this.samlAssertion);
			} else {
				this.wsSecuritySOAPHandler.setCredentials(this.samlAssertion, this.privateKey);
			}
		}
	}

	/**
	 * Uploads a given document to the DSS in preparation of a signing ceremony.
	 *
	 * @param mimetype
	 *            the mime-type of the document.
	 * @param signatureType
	 *            the optional signature type. If none is provided, the DSS will
	 *            select the most appropriate.
	 * @param data
	 *            the data bytes of the document.
	 * @param useAttachments
	 *            set to <code>true</code> to use SOAP attachments.
	 * @param requestAttestation
	 *            set to <code>true</code> if the DSS should return a SAML
	 *            attestation during the document download.
	 * @return a session object. Should be saved within the HTTP session for
	 *         later usage.
	 * @throws UnsupportedDocumentTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws AuthenticationRequiredException
	 * @throws ApplicationDocumentAuthorizedException
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, SignatureType signatureType, byte[] data,
			boolean useAttachments, boolean requestAttestation)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, ApplicationDocumentAuthorizedException {
		SignRequest signRequest = this.objectFactory.createSignRequest();
		signRequest.setProfile(DigitalSignatureServiceConstants.PROFILE);

		InputDocuments inputDocuments = this.objectFactory.createInputDocuments();
		signRequest.setInputDocuments(inputDocuments);
		DocumentType document = addDocument(mimetype, data, useAttachments, inputDocuments);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		signRequest.setOptionalInputs(optionalInputs);

		optionalInputs.getAny()
				.add(this.objectFactory.createAdditionalProfile(DigitalSignatureServiceConstants.DSS_ASYNC_PROFILE));

		RequestSecurityTokenType requestSecurityToken = this.wstObjectFactory.createRequestSecurityTokenType();
		optionalInputs.getAny().add(this.wstObjectFactory.createRequestSecurityToken(requestSecurityToken));
		requestSecurityToken.getAny()
				.add(this.wstObjectFactory.createTokenType(DigitalSignatureServiceConstants.WS_SEC_CONV_TOKEN_TYPE));
		requestSecurityToken.getAny().add(
				this.wstObjectFactory.createRequestType(DigitalSignatureServiceConstants.WS_TRUST_ISSUE_REQUEST_TYPE));
		EntropyType entropy = this.wstObjectFactory.createEntropyType();
		BinarySecretType binarySecret = this.wstObjectFactory.createBinarySecretType();
		binarySecret.setType(DigitalSignatureServiceConstants.WS_TRUST_BINARY_SECRET_NONCE_TYPE);
		byte[] nonce = new byte[256 / 8];
		this.secureRandom.setSeed(System.currentTimeMillis());
		this.secureRandom.nextBytes(nonce);
		binarySecret.setValue(nonce);
		entropy.getAny().add(this.wstObjectFactory.createBinarySecret(binarySecret));
		requestSecurityToken.getAny().add(this.wstObjectFactory.createEntropy(entropy));
		requestSecurityToken.getAny().add(this.wstObjectFactory.createKeySize(256L));

		SignaturePlacement signaturePlacement = this.objectFactory.createSignaturePlacement();
		optionalInputs.getAny().add(signaturePlacement);
		signaturePlacement.setCreateEnvelopedSignature(true);
		signaturePlacement.setWhichDocument(document);

		if (null != signatureType) {
			optionalInputs.getAny().add(this.objectFactory.createSignatureType(signatureType.getUri()));
		}

		if (requestAttestation) {
			AttestationRequestType attestationRequest = this.dsspObjectFactory.createAttestationRequestType();
			optionalInputs.getAny().add(this.dsspObjectFactory.createAttestationRequest(attestationRequest));
		}

		String responseId = null;
		String securityTokenId = null;
		byte[] serverNonce = null;

		configureCredentials();
		SignResponse signResponse = this.dssPort.sign(signRequest);

		Result result = signResponse.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.PENDING_RESULT_MAJOR.equals(resultMajor)) {
			if (DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR.equals(resultMajor)) {
				if (DigitalSignatureServiceConstants.UNSUPPORTED_MIME_TYPE_RESULT_MINOR.equals(resultMinor)) {
					throw new UnsupportedDocumentTypeException();
				} else if (DigitalSignatureServiceConstants.UNSUPPORTED_SIGNATURE_TYPE_RESULT_MINOR
						.equals(resultMinor)) {
					throw new UnsupportedSignatureTypeException();
				} else if (DigitalSignatureServiceConstants.INCORRECT_SIGNATURE_TYPE_RESULT_MINOR.equals(resultMinor)) {
					throw new IncorrectSignatureTypeException();
				} else if (DigitalSignatureServiceConstants.AUTHENTICATION_REQUIRED_RESULT_MINOR.equals(resultMinor)) {
					throw new AuthenticationRequiredException();
				} else if (DigitalSignatureServiceConstants.SUBJECT_NOT_AUTHORIZED_RESULT_MINOR.equals(resultMinor)) {
					throw new ApplicationDocumentAuthorizedException();
				}
			}
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}

		AnyType optionalOutputs = signResponse.getOptionalOutputs();
		List<Object> optionalOutputsList = optionalOutputs.getAny();
		for (Object optionalOutputsObject : optionalOutputsList) {
			LOGGER.debug("optional outputs object type: {}", optionalOutputsObject.getClass().getName());
			if (optionalOutputsObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) optionalOutputsObject;
				QName name = jaxbElement.getName();
				LOGGER.debug("value name: {}", name);
				if (DigitalSignatureServiceConstants.ASYNC_RESPONSEID_QNAME.equals(name)) {
					responseId = (String) jaxbElement.getValue();
					LOGGER.debug("async:ResponseID = {}", responseId);
				} else if (jaxbElement.getValue() instanceof RequestSecurityTokenResponseCollectionType) {
					RequestSecurityTokenResponseCollectionType requestSecurityTokenResponseCollection = (RequestSecurityTokenResponseCollectionType) jaxbElement
							.getValue();
					List<RequestSecurityTokenResponseType> rstsList = requestSecurityTokenResponseCollection
							.getRequestSecurityTokenResponse();
					if (rstsList.size() == 1) {
						RequestSecurityTokenResponseType rstr = rstsList.get(0);
						for (Object rstrObject : rstr.getAny()) {
							JAXBElement rstrElement = (JAXBElement) rstrObject;
							if (rstrElement.getValue() instanceof RequestedSecurityTokenType) {
								RequestedSecurityTokenType requestedSecurityToken = (RequestedSecurityTokenType) rstrElement
										.getValue();
								SecurityContextTokenType securityContextToken = ((JAXBElement<SecurityContextTokenType>) requestedSecurityToken
										.getAny()).getValue();
								securityTokenId = ((JAXBElement<String>) securityContextToken.getAny().get(0))
										.getValue();
								LOGGER.debug("security token id: {}", securityTokenId);
							} else if (rstrElement.getValue() instanceof EntropyType) {
								EntropyType serverEntropy = (EntropyType) rstrElement.getValue();
								BinarySecretType serverBinarySecret = ((JAXBElement<BinarySecretType>) serverEntropy
										.getAny().get(0)).getValue();
								serverNonce = serverBinarySecret.getValue();
							}
						}
					}
				}
			}
		}

		if (null == responseId) {
			throw new RuntimeException("missing async:ResponseID in response");
		}

		if (null == securityTokenId) {
			throw new RuntimeException("missing WS-SecureConversation token identifier");
		}

		if (null == serverNonce) {
			throw new RuntimeException("missing Nonce in response");
		}
		P_SHA1 p_SHA1 = new P_SHA1();
		byte[] key;
		try {
			key = p_SHA1.createKey(nonce, serverNonce, 0, 256 / 8);
		} catch (ConversationException e) {
			throw new RuntimeException("error generating P_SHA1 key");
		}

		Element securityTokenElement = this.wsTrustSOAPHandler.getRequestedSecurityToken();
		DigitalSignatureServiceSession digitalSignatureServiceSession = new DigitalSignatureServiceSession(responseId,
				securityTokenId, key, securityTokenElement);
		return digitalSignatureServiceSession;
	}

	/**
	 * Downloads the signed document.
	 *
	 * @param session
	 *            the session object.
	 * @return the signed document.
	 */
	public DownloadResult downloadSignedDocumentResult(DigitalSignatureServiceSession session) {
		byte[] signedDocument = downloadSignedDocument(session);
		Element attestation = this.attestationSOAPHandler.getAttestation();
		DownloadResult downloadResult = new DownloadResult(signedDocument, attestation);
		return downloadResult;
	}

	/**
	 * Downloads the signed document.
	 *
	 * @param session
	 *            the session object.
	 * @return the signed document.
	 */
	public byte[] downloadSignedDocument(DigitalSignatureServiceSession session) {

		if (false == session.isSignResponseVerified()) {
			throw new SecurityException("SignResponse not verified");
		}

		PendingRequest pendingRequest = this.asyncObjectFactory.createPendingRequest();
		pendingRequest.setProfile(DigitalSignatureServiceConstants.PROFILE);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		pendingRequest.setOptionalInputs(optionalInputs);

		optionalInputs.getAny()
				.add(this.objectFactory.createAdditionalProfile(DigitalSignatureServiceConstants.DSS_ASYNC_PROFILE));

		optionalInputs.getAny().add(this.asyncObjectFactory.createResponseID(session.getResponseId()));

		RequestSecurityTokenType requestSecurityToken = this.wstObjectFactory.createRequestSecurityTokenType();
		optionalInputs.getAny().add(this.wstObjectFactory.createRequestSecurityToken(requestSecurityToken));
		requestSecurityToken.getAny().add(
				this.wstObjectFactory.createRequestType(DigitalSignatureServiceConstants.WS_TRUST_CANCEL_REQUEST_TYPE));
		CancelTargetType cancelTarget = this.wstObjectFactory.createCancelTargetType();
		requestSecurityToken.getAny().add(this.wstObjectFactory.createCancelTarget(cancelTarget));
		SecurityTokenReferenceType securityTokenReference = this.wsseObjectFactory.createSecurityTokenReferenceType();
		cancelTarget.setAny(this.wsseObjectFactory.createSecurityTokenReference(securityTokenReference));
		ReferenceType reference = this.wsseObjectFactory.createReferenceType();
		securityTokenReference.getAny().add(this.wsseObjectFactory.createReference(reference));
		reference.setValueType(DigitalSignatureServiceConstants.WS_SEC_CONV_TOKEN_TYPE);
		reference.setURI(session.getSecurityTokenId());

		this.wsSecuritySOAPHandler.setSession(session);
		SignResponse signResponse = this.dssPort.pendingRequest(pendingRequest);

		Result result = signResponse.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR.equals(resultMajor)) {
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}

		return getDocument(signResponse);
	}

	private byte[] getDocument(SignResponse signResponse) {
		AnyType optionalOutputs = signResponse.getOptionalOutputs();
		List<Object> optionalOutputsList = optionalOutputs.getAny();
		for (Object optionalOutputsObject : optionalOutputsList) {
			LOGGER.debug("optional outputs object type: {}", optionalOutputsObject.getClass().getName());
			if (optionalOutputsObject instanceof DocumentWithSignature) {
				DocumentWithSignature documentWithSignature = (DocumentWithSignature) optionalOutputsObject;
				DocumentType document = documentWithSignature.getDocument();
				if (document.getBase64XML() != null) {
					return document.getBase64XML();
				}
				if (document.getBase64Data() != null) {
					return document.getBase64Data().getValue();
				}
				if (document.getAttachmentReference() != null) {
					AttachmentReferenceType attachmentReference = document.getAttachmentReference();
					String attachmentUri = attachmentReference.getAttRefURI();
					LOGGER.debug("attachment URI: {}", attachmentUri);
					// skip 'cid:'
					String attachmentContentId = attachmentUri.substring(4);
					LOGGER.debug("attachment content id: {}", attachmentContentId);
					Map<String, DataHandler> inboundAttachments = this.attachmentsSOAPHandler.getInboundAttachments();
					for (String attachmentId : inboundAttachments.keySet()) {
						LOGGER.debug("actual attachment id: {}", attachmentId);
					}
					DataHandler dataHandler;
					if (inboundAttachments.size() == 1) {
						dataHandler = inboundAttachments.values().iterator().next();
					} else {
						// JAX-WS RI 1.8 and CXF
						dataHandler = inboundAttachments.get(attachmentContentId);
						if (null == dataHandler) {
							// JAX-WS RI 1.7 adds '<' and '>'.
							attachmentContentId = '<' + attachmentContentId + '>';
							dataHandler = inboundAttachments.get(attachmentContentId);
						}
					}
					LOGGER.debug("received data handler: {}", (null != dataHandler));
					try {
						byte[] signedDocument = IOUtils.toByteArray(dataHandler.getInputStream());
						LOGGER.debug("signed document size: {}", signedDocument.length);
						return signedDocument;
					} catch (IOException e) {
						throw new RuntimeException("IO error: " + e.getMessage(), e);
					}
				}
			}
		}

		return null;
	}

	/**
	 * Verifies the signatures on the given document.
	 *
	 * @param mimetype
	 *            the mime-type of the document.
	 * @param data
	 *            the document data.
	 * @return the verification result.
	 * @throws UnsupportedDocumentTypeException
	 *             for unsupported mime-types
	 * @throws DocumentSignatureException
	 *             when the document or signature is incorrect.
	 */
	public VerificationResult verify(String mimetype, byte[] data)
			throws UnsupportedDocumentTypeException, DocumentSignatureException {
		return verify(mimetype, data, false);
	}

	/**
	 * Verifies the signatures on the given document.
	 *
	 * @param mimetype
	 *            the mime-type of the document.
	 * @param data
	 *            the document data.
	 * @param useAttachments
	 *            <code>true</code> when you want to use SOAP attachments.
	 * @return the verification result.
	 * @throws UnsupportedDocumentTypeException
	 *             for unsupported mime-types
	 * @throws DocumentSignatureException
	 *             when the document or signature is incorrect.
	 */
	public VerificationResult verify(String mimetype, byte[] data, boolean useAttachments)
			throws UnsupportedDocumentTypeException, DocumentSignatureException {
		List<SignatureInfo> signatureInfos = new LinkedList<SignatureInfo>();

		VerifyRequest verifyRequest = this.objectFactory.createVerifyRequest();
		verifyRequest.setProfile(DigitalSignatureServiceConstants.PROFILE);
		InputDocuments inputDocuments = this.objectFactory.createInputDocuments();
		verifyRequest.setInputDocuments(inputDocuments);
		addDocument(mimetype, data, useAttachments, inputDocuments);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		verifyRequest.setOptionalInputs(optionalInputs);
		ReturnVerificationReport returnVerificationReport = this.vrObjectFactory.createReturnVerificationReport();
		optionalInputs.getAny().add(returnVerificationReport);
		returnVerificationReport.setIncludeVerifier(false);
		returnVerificationReport.setIncludeCertificateValues(true);

		this.wsSecuritySOAPHandler.setSession(null);
		configureCredentials();

		ResponseBaseType response = this.dssPort.verify(verifyRequest);

		Result result = response.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR.equals(resultMajor)) {
			if (DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR.equals(resultMajor)) {
				if (DigitalSignatureServiceConstants.UNSUPPORTED_MIME_TYPE_RESULT_MINOR.equals(resultMinor)) {
					throw new UnsupportedDocumentTypeException();
				}
				if (DigitalSignatureServiceConstants.INCORRECT_SIGNATURE_RESULT_MINOR.equals(resultMinor)) {
					throw new DocumentSignatureException();
				}
			}
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}

		DateTime timeStampRenewalBefore = null;
		AnyType optionalOutputs = response.getOptionalOutputs();
		List<Object> optionalOutputsList = optionalOutputs.getAny();
		for (Object optionalOutput : optionalOutputsList) {
			if (false == optionalOutput instanceof JAXBElement) {
				continue;
			}
			JAXBElement jaxbElement = (JAXBElement) optionalOutput;
			LOGGER.debug("optional output: {}", optionalOutput.getClass().getName());
			if (jaxbElement.getValue() instanceof DeadlineType) {
				DeadlineType deadlineType = (DeadlineType) jaxbElement.getValue();
				timeStampRenewalBefore = new DateTime(deadlineType.getBefore().toGregorianCalendar());
			} else if (jaxbElement.getValue() instanceof VerificationReportType) {
				LOGGER.debug("found VerificationReport");
				VerificationReportType verificationReport = (VerificationReportType) jaxbElement.getValue();
				List<IndividualReportType> individualReports = verificationReport.getIndividualReport();
				for (IndividualReportType individualReport : individualReports) {

					if (!DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR
							.equals(individualReport.getResult().getResultMajor())) {
						LOGGER.warn("some invalid VR result reported: {}",
								individualReport.getResult().getResultMajor());
						continue;
					}
					SignedObjectIdentifierType signedObjectIdentifier = individualReport.getSignedObjectIdentifier();
					Date signingTime = signedObjectIdentifier.getSignedProperties().getSignedSignatureProperties()
							.getSigningTime().toGregorianCalendar().getTime();
					String location = signedObjectIdentifier.getSignedProperties().getSignedSignatureProperties()
							.getLocation();
					SignerRoleType signerRole = signedObjectIdentifier.getSignedProperties()
							.getSignedSignatureProperties().getSignerRole();
					String role = null;
					if (null != signerRole) {
						ClaimedRolesListType claimedRolesList = signerRole.getClaimedRoles();
						if (null != claimedRolesList) {
							List<be.e_contract.dssp.ws.jaxb.xades.AnyType> claimedRoles = claimedRolesList
									.getClaimedRole();
							be.e_contract.dssp.ws.jaxb.xades.AnyType claimedRole = claimedRoles.get(0);
							role = claimedRole.getContent().get(0).toString();
						}
					}

					List<Object> details = individualReport.getDetails().getAny();
					X509Certificate certificate = null;
					String name = null;
					for (Object detail : details) {
						if (detail instanceof JAXBElement<?>) {
							JAXBElement<?> detailElement = (JAXBElement<?>) detail;
							if (detailElement.getValue() instanceof DetailedSignatureReportType) {
								DetailedSignatureReportType detailedSignatureReport = (DetailedSignatureReportType) detailElement
										.getValue();

								List<CertificateValidityType> certificateValidities = detailedSignatureReport
										.getCertificatePathValidity().getPathValidityDetail().getCertificateValidity();
								CertificateValidityType certificateValidity = certificateValidities.get(0);
								name = certificateValidity.getSubject();
								byte[] encodedCertificate = certificateValidity.getCertificateValue();
								try {
									certificate = (X509Certificate) this.certificateFactory
											.generateCertificate(new ByteArrayInputStream(encodedCertificate));
								} catch (CertificateException e) {
									throw new RuntimeException("cert decoding error: " + e.getMessage(), e);
								}
							}
						}
					}
					signatureInfos.add(new SignatureInfo(name, certificate, signingTime, role, location));
				}
			}
		}

		if (signatureInfos.isEmpty()) {
			return null;
		}
		return new VerificationResult(signatureInfos, timeStampRenewalBefore);
	}

	public DownloadResult eSeal(String mimetype, byte[] data)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, KeyLookupException, KeyInfoNotProvidedException {
		return eSeal(mimetype, data, null, false, null, null, false);
	}

	public DownloadResult eSeal(String mimetype, byte[] data, String keyName)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, KeyLookupException, KeyInfoNotProvidedException {
		return eSeal(mimetype, data, keyName, false, null, null, false);
	}

	/**
	 * Creates an eSeal on a given document.
	 *
	 * @param mimetype
	 *            the mime-type of the document.
	 * @param data
	 *            the document.
	 * @param keyName
	 *            the optional key name.
	 * @param useAttachments
	 *            whether to use SOAP with attachments.
	 * @param signatureType
	 *            the optional signature type.
	 * @param visibleSignatureConfiguration
	 *            the optional visible signature configuration.
	 * @param requestAttestation
	 *            whether to return a DSS attestation.
	 * @return the sealed document.
	 * @throws UnsupportedDocumentTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws AuthenticationRequiredException
	 * @throws KeyLookupException
	 * @throws KeyInfoNotProvidedException
	 */
	public DownloadResult eSeal(String mimetype, byte[] data, String keyName, boolean useAttachments,
			SignatureType signatureType, VisibleSignatureConfiguration visibleSignatureConfiguration,
			boolean requestAttestation)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException, KeyLookupException, KeyInfoNotProvidedException {
		SignRequest signRequest = this.objectFactory.createSignRequest();
		signRequest.setProfile(DigitalSignatureServiceConstants.ESEAL_PROFILE);

		InputDocuments inputDocuments = this.objectFactory.createInputDocuments();
		signRequest.setInputDocuments(inputDocuments);
		DocumentType document = addDocument(mimetype, data, useAttachments, inputDocuments);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		signRequest.setOptionalInputs(optionalInputs);

		SignaturePlacement signaturePlacement = this.objectFactory.createSignaturePlacement();
		optionalInputs.getAny().add(signaturePlacement);
		signaturePlacement.setCreateEnvelopedSignature(true);
		signaturePlacement.setWhichDocument(document);

		if (null != signatureType) {
			optionalInputs.getAny().add(this.objectFactory.createSignatureType(signatureType.getUri()));
		}

		if (requestAttestation) {
			AttestationRequestType attestationRequest = this.dsspObjectFactory.createAttestationRequestType();
			optionalInputs.getAny().add(this.dsspObjectFactory.createAttestationRequest(attestationRequest));
		}

		if (null != keyName) {
			KeySelector keySelector = this.objectFactory.createKeySelector();
			optionalInputs.getAny().add(keySelector);
			KeyInfoType keyInfo = this.dsObjectFactory.createKeyInfoType();
			keySelector.setKeyInfo(keyInfo);
			keyInfo.getContent().add(this.dsObjectFactory.createKeyName(keyName));
		}

		if (null != visibleSignatureConfiguration) {
			VisibleSignatureConfigurationType visSigConfig = this.vsObjectFactory
					.createVisibleSignatureConfigurationType();
			optionalInputs.getAny().add(this.vsObjectFactory.createVisibleSignatureConfiguration(visSigConfig));
			VisibleSignaturePolicyType visibleSignaturePolicy = VisibleSignaturePolicyType.DOCUMENT_SUBMISSION_POLICY;
			visSigConfig.setVisibleSignaturePolicy(visibleSignaturePolicy);
			VisibleSignatureItemsConfigurationType visibleSignatureItemsConfiguration = this.vsObjectFactory
					.createVisibleSignatureItemsConfigurationType();
			visSigConfig.setVisibleSignatureItemsConfiguration(visibleSignatureItemsConfiguration);
			if (visibleSignatureConfiguration.getLocation() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = this.vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(locationVisibleSignatureItem);
				locationVisibleSignatureItem.setItemName(ItemNameEnum.SIGNATURE_PRODUCTION_PLACE);
				ItemValueStringType itemValue = this.vsObjectFactory.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getLocation());
			}
			if (visibleSignatureConfiguration.getRole() != null) {
				VisibleSignatureItemType locationVisibleSignatureItem = this.vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(locationVisibleSignatureItem);
				locationVisibleSignatureItem.setItemName(ItemNameEnum.SIGNATURE_REASON);
				ItemValueStringType itemValue = this.vsObjectFactory.createItemValueStringType();
				locationVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getRole());
			}
			if (visibleSignatureConfiguration.getSignerImageUri() != null) {
				PixelVisibleSignaturePositionType visibleSignaturePosition = this.vsObjectFactory
						.createPixelVisibleSignaturePositionType();
				visSigConfig.setVisibleSignaturePosition(visibleSignaturePosition);
				visibleSignaturePosition.setPageNumber(BigInteger.valueOf(visibleSignatureConfiguration.getPage()));
				visibleSignaturePosition.setX(BigInteger.valueOf(visibleSignatureConfiguration.getX()));
				visibleSignaturePosition.setY(BigInteger.valueOf(visibleSignatureConfiguration.getY()));

				VisibleSignatureItemType visibleSignatureItem = this.vsObjectFactory.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(visibleSignatureItem);
				visibleSignatureItem.setItemName(ItemNameEnum.SIGNER_IMAGE);
				ItemValueURIType itemValue = this.vsObjectFactory.createItemValueURIType();
				itemValue.setItemValue(visibleSignatureConfiguration.getSignerImageUri());
				visibleSignatureItem.setItemValue(itemValue);
			}
			if (visibleSignatureConfiguration.getCustomText() != null) {
				VisibleSignatureItemType customTextVisibleSignatureItem = this.vsObjectFactory
						.createVisibleSignatureItemType();
				visibleSignatureItemsConfiguration.getVisibleSignatureItem().add(customTextVisibleSignatureItem);
				customTextVisibleSignatureItem.setItemName(ItemNameEnum.CUSTOM_TEXT);
				ItemValueStringType itemValue = this.vsObjectFactory.createItemValueStringType();
				customTextVisibleSignatureItem.setItemValue(itemValue);
				itemValue.setItemValue(visibleSignatureConfiguration.getCustomText());
			}
		}

		configureCredentials();
		SignResponse signResponse = this.dssPort.sign(signRequest);

		Result result = signResponse.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR.equals(resultMajor)) {
			if (DigitalSignatureServiceConstants.REQUESTER_ERROR_RESULT_MAJOR.equals(resultMajor)) {
				if (DigitalSignatureServiceConstants.UNSUPPORTED_MIME_TYPE_RESULT_MINOR.equals(resultMinor)) {
					throw new UnsupportedDocumentTypeException();
				} else if (DigitalSignatureServiceConstants.UNSUPPORTED_SIGNATURE_TYPE_RESULT_MINOR
						.equals(resultMinor)) {
					throw new UnsupportedSignatureTypeException();
				} else if (DigitalSignatureServiceConstants.INCORRECT_SIGNATURE_TYPE_RESULT_MINOR.equals(resultMinor)) {
					throw new IncorrectSignatureTypeException();
				} else if (DigitalSignatureServiceConstants.AUTHENTICATION_REQUIRED_RESULT_MINOR.equals(resultMinor)) {
					throw new AuthenticationRequiredException();
				} else if (DigitalSignatureServiceConstants.KEY_INFO_NOT_PROVIDED_RESULT_MINOR.equals(resultMinor)) {
					throw new KeyInfoNotProvidedException();
				}
			} else if (DigitalSignatureServiceConstants.RESPONDER_ERROR_RESULT_MAJOR.equals(resultMajor)) {
				if (DigitalSignatureServiceConstants.KEY_LOOKUP_FAILED_RESULT_MINOR.equals(resultMinor)) {
					throw new KeyLookupException();
				}
			}
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}

		byte[] signedDocument = getDocument(signResponse);
		Element attestation = this.attestationSOAPHandler.getAttestation();
		DownloadResult downloadResult = new DownloadResult(signedDocument, attestation);
		return downloadResult;
	}

	private DocumentType addDocument(String mimetype, byte[] data, boolean useAttachments,
			InputDocuments inputDocuments) {
		DocumentType document = this.objectFactory.createDocumentType();
		String documentId = "document-" + UUID.randomUUID().toString();
		document.setID(documentId);
		inputDocuments.getDocumentOrTransformedDataOrDocumentHash().add(document);
		if (useAttachments) {
			AttachmentReferenceType attachmentReference = this.objectFactory.createAttachmentReferenceType();
			document.setAttachmentReference(attachmentReference);
			attachmentReference.setMimeType(mimetype);
			DigestMethodType digestMethod = this.dsObjectFactory.createDigestMethodType();
			digestMethod.setAlgorithm(DigitalSignatureServiceConstants.SHA1_DIGEST_METHOD_TYPE);
			attachmentReference.setDigestMethod(digestMethod);
			MessageDigest messageDigest;
			try {
				messageDigest = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("SHA-1 algo error: " + e.getMessage(), e);
			}
			byte[] digest = messageDigest.digest(data);
			attachmentReference.setDigestValue(digest);

			String contentId = addAttachment(mimetype, data);
			String attachmentUri = "cid:" + contentId;
			attachmentReference.setAttRefURI(attachmentUri);
		} else {
			if ("application/xml".equals(mimetype)) {
				document.setBase64XML(data);
			} else {
				Base64Data base64Data = this.objectFactory.createBase64Data();
				base64Data.setMimeType(mimetype);
				base64Data.setValue(data);
				document.setBase64Data(base64Data);
			}
		}
		return document;
	}

	private String addAttachment(String mimetype, byte[] data) {
		String contentId = UUID.randomUUID().toString();
		LOGGER.debug("adding attachment: {}", contentId);
		DataSource dataSource = new ByteArrayDataSource(data, mimetype);
		DataHandler dataHandler = new DataHandler(dataSource);
		BindingProvider bindingProvider = (BindingProvider) this.dssPort;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		Map<String, DataHandler> outputMessageAttachments = new HashMap<String, DataHandler>();
		requestContext.put(MessageContext.OUTBOUND_MESSAGE_ATTACHMENTS, outputMessageAttachments);
		outputMessageAttachments.put(contentId, dataHandler);
		return contentId;
	}

	/**
	 * Initialize a signature using the OASIS DSS localsig two-step approach.
	 *
	 * @param mimetype
	 * @param data
	 * @param signatureType
	 * @param useAttachments
	 * @param digestAlgo
	 * @param signingCertificateChain
	 * @return
	 * @throws UnsupportedDocumentTypeException
	 * @throws UnsupportedSignatureTypeException
	 * @throws IncorrectSignatureTypeException
	 * @throws AuthenticationRequiredException
	 */
	public TwoStepSession prepareSignature(String mimetype, byte[] data, SignatureType signatureType,
			boolean useAttachments, String digestAlgo, List<X509Certificate> signingCertificateChain)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException {
		SignRequest signRequest = this.objectFactory.createSignRequest();
		signRequest.setProfile(DigitalSignatureServiceConstants.LOCALSIG_PROFILE);

		InputDocuments inputDocuments = this.objectFactory.createInputDocuments();
		signRequest.setInputDocuments(inputDocuments);
		DocumentType document = addDocument(mimetype, data, useAttachments, inputDocuments);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		signRequest.setOptionalInputs(optionalInputs);

		JAXBElement<String> servicePolicyElement = this.objectFactory
				.createServicePolicy(DigitalSignatureServiceConstants.TWO_STEP_APPROACH_SERVICE_POLICY);
		optionalInputs.getAny().add(servicePolicyElement);

		SignaturePlacement signaturePlacement = this.objectFactory.createSignaturePlacement();
		optionalInputs.getAny().add(signaturePlacement);
		signaturePlacement.setCreateEnvelopedSignature(true);
		signaturePlacement.setWhichDocument(document);

		if (null != signatureType) {
			optionalInputs.getAny().add(this.objectFactory.createSignatureType(signatureType.getUri()));
		}

		ReturnDocumentHash returnDocumentHash = this.localsigObjectFactory.createReturnDocumentHash();
		returnDocumentHash.setMaintainRequestState(true);
		DigestMethodType digestMethod = this.dsObjectFactory.createDigestMethodType();
		digestMethod.setAlgorithm(digestAlgoToDigestMethod.get(digestAlgo));
		returnDocumentHash.setDigestMethod(digestMethod);
		optionalInputs.getAny().add(returnDocumentHash);

		AdditionalKeyInfo additionalKeyInfo = this.objectFactory.createAdditionalKeyInfo();
		KeyInfoType keyInfo = this.dsObjectFactory.createKeyInfoType();
		X509DataType x509Data = this.dsObjectFactory.createX509DataType();
		keyInfo.getContent().add(this.dsObjectFactory.createX509Data(x509Data));
		for (X509Certificate certificate : signingCertificateChain) {
			try {
				x509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName()
						.add(this.dsObjectFactory.createX509DataTypeX509Certificate(certificate.getEncoded()));
			} catch (CertificateEncodingException e) {
				throw new RuntimeException("X509 certificate error: " + e.getMessage(), e);
			}
		}
		additionalKeyInfo.setKeyInfo(keyInfo);
		optionalInputs.getAny().add(additionalKeyInfo);

		configureCredentials();
		SignResponse signResponse = this.dssPort.sign(signRequest);

		if (null == signResponse) {
			throw new RuntimeException("missing dss:SignResponse");
		}

		Result result = signResponse.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR.equals(resultMajor)) {
			if (DigitalSignatureServiceConstants.UNSUPPORTED_MIME_TYPE_RESULT_MINOR.equals(resultMinor)) {
				throw new UnsupportedDocumentTypeException();
			} else if (DigitalSignatureServiceConstants.UNSUPPORTED_SIGNATURE_TYPE_RESULT_MINOR.equals(resultMinor)) {
				throw new UnsupportedSignatureTypeException();
			} else if (DigitalSignatureServiceConstants.INCORRECT_SIGNATURE_TYPE_RESULT_MINOR.equals(resultMinor)) {
				throw new IncorrectSignatureTypeException();
			} else if (DigitalSignatureServiceConstants.AUTHENTICATION_REQUIRED_RESULT_MINOR.equals(resultMinor)) {
				throw new AuthenticationRequiredException();
			}
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}
		if (!signResponse.getProfile().equals(DigitalSignatureServiceConstants.LOCALSIG_PROFILE)) {
			throw new RuntimeException("incorrect profile: " + signResponse.getProfile());
		}
		if (!resultMinor.equals(DigitalSignatureServiceConstants.DOCUMENT_HASH_RESULT_MINOR)) {
			throw new RuntimeException("unexpected result minor: " + resultMinor);
		}

		String correlationId = null;
		byte[] digestValue = null;
		AnyType optionalOutputs = signResponse.getOptionalOutputs();
		List<Object> optionalOutputsList = optionalOutputs.getAny();
		for (Object optionalOutputsObject : optionalOutputsList) {
			LOGGER.debug("optional outputs object type: {}", optionalOutputsObject.getClass().getName());
			if (optionalOutputsObject instanceof JAXBElement) {
				JAXBElement<?> optionalOutputElement = (JAXBElement<?>) optionalOutputsObject;
				LOGGER.debug("optional output qname: {}", optionalOutputElement.getName());
				if (DigitalSignatureServiceConstants.CORRELATION_ID_QNAME.equals(optionalOutputElement.getName())) {
					correlationId = (String) optionalOutputElement.getValue();
				}
			} else if (optionalOutputsObject instanceof DocumentHash) {
				DocumentHash documentHash = (DocumentHash) optionalOutputsObject;
				digestValue = documentHash.getDigestValue();
			}
		}

		TwoStepSession twoStepSession = new TwoStepSession(correlationId, digestAlgo, digestValue);
		return twoStepSession;
	}

	/**
	 * Finalize a signature using the OASIS DSS localsig two-step approach.
	 *
	 * @param session
	 * @param signatureValue
	 * @return
	 */
	public byte[] performSignature(TwoStepSession session, byte[] signatureValue) {
		SignRequest signRequest = this.objectFactory.createSignRequest();
		signRequest.setProfile(DigitalSignatureServiceConstants.LOCALSIG_PROFILE);

		AnyType optionalInputs = this.objectFactory.createAnyType();
		signRequest.setOptionalInputs(optionalInputs);

		JAXBElement<String> servicePolicyElement = this.objectFactory
				.createServicePolicy(DigitalSignatureServiceConstants.TWO_STEP_APPROACH_SERVICE_POLICY);
		optionalInputs.getAny().add(servicePolicyElement);

		JAXBElement<String> correlationId = this.localsigObjectFactory.createCorrelationID(session.getCorrelationId());
		optionalInputs.getAny().add(correlationId);

		SignatureObject signatureObject = this.objectFactory.createSignatureObject();
		optionalInputs.getAny().add(signatureObject);
		Base64Signature base64Signature = this.objectFactory.createBase64Signature();
		base64Signature.setValue(signatureValue);
		signatureObject.setBase64Signature(base64Signature);

		configureCredentials();
		SignResponse signResponse = this.dssPort.sign(signRequest);

		Result result = signResponse.getResult();
		String resultMajor = result.getResultMajor();
		String resultMinor = result.getResultMinor();
		if (false == DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR.equals(resultMajor)) {
			throw new RuntimeException("not successfull: " + resultMajor + " " + resultMinor);
		}
		if (!signResponse.getProfile().equals(DigitalSignatureServiceConstants.LOCALSIG_PROFILE)) {
			throw new RuntimeException("incorrect profile: " + signResponse.getProfile());
		}

		return getDocument(signResponse);
	}
}
