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

package be.e_contract.dssp.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.DigitalSignatureServiceFactory;
import be.e_contract.dssp.ws.jaxb.dss.AnyType;
import be.e_contract.dssp.ws.jaxb.dss.AttachmentReferenceType;
import be.e_contract.dssp.ws.jaxb.dss.Base64Data;
import be.e_contract.dssp.ws.jaxb.dss.DocumentType;
import be.e_contract.dssp.ws.jaxb.dss.DocumentWithSignature;
import be.e_contract.dssp.ws.jaxb.dss.InputDocuments;
import be.e_contract.dssp.ws.jaxb.dss.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.dss.ResponseBaseType;
import be.e_contract.dssp.ws.jaxb.dss.Result;
import be.e_contract.dssp.ws.jaxb.dss.SignRequest;
import be.e_contract.dssp.ws.jaxb.dss.SignResponse;
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
import be.e_contract.dssp.ws.jaxb.dssp.DeadlineType;
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

	private final be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory wsseObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory vrObjectFactory;

	private final CertificateFactory certificateFactory;

	private String username;

	private String password;

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
		// cannot add LoggingSOAPHandler here, else we break SOAP with
		// attachments on Apache CXF
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.wstObjectFactory = new be.e_contract.dssp.ws.jaxb.wst.ObjectFactory();
		this.dsObjectFactory = new be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory();
		this.asyncObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory();
		this.wsseObjectFactory = new be.e_contract.dssp.ws.jaxb.wsse.ObjectFactory();
		this.vrObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory();

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());

		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
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
		this.username = username;
		this.password = password;
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
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, SignatureType signatureType, byte[] data)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException {
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
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, byte[] data)
			throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException, IncorrectSignatureTypeException,
			AuthenticationRequiredException {
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
	 */
	public DigitalSignatureServiceSession uploadDocument(String mimetype, SignatureType signatureType, byte[] data,
			boolean useAttachments) throws UnsupportedDocumentTypeException, UnsupportedSignatureTypeException,
			IncorrectSignatureTypeException, AuthenticationRequiredException {
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

		String responseId = null;
		String securityTokenId = null;
		byte[] serverNonce = null;

		this.wsSecuritySOAPHandler.setCredentials(this.username, this.password);
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
}
