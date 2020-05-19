/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2013-2019 e-Contract.be BVBA.
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
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.mail.util.ByteArrayDataSource;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.BindingType;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.SOAPBinding;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.dssp.ws.DigitalSignatureServiceConstants;
import be.e_contract.dssp.ws.jaxb.dss.AnyType;
import be.e_contract.dssp.ws.jaxb.dss.AttachmentReferenceType;
import be.e_contract.dssp.ws.jaxb.dss.Base64Data;
import be.e_contract.dssp.ws.jaxb.dss.DocumentHash;
import be.e_contract.dssp.ws.jaxb.dss.DocumentType;
import be.e_contract.dssp.ws.jaxb.dss.DocumentWithSignature;
import be.e_contract.dssp.ws.jaxb.dss.ObjectFactory;
import be.e_contract.dssp.ws.jaxb.dss.ResponseBaseType;
import be.e_contract.dssp.ws.jaxb.dss.Result;
import be.e_contract.dssp.ws.jaxb.dss.SignRequest;
import be.e_contract.dssp.ws.jaxb.dss.SignResponse;
import be.e_contract.dssp.ws.jaxb.dss.VerifyRequest;
import be.e_contract.dssp.ws.jaxb.dss.async.PendingRequest;
import be.e_contract.dssp.ws.jaxb.dss.vr.CertificatePathValidityType;
import be.e_contract.dssp.ws.jaxb.dss.vr.CertificatePathValidityVerificationDetailType;
import be.e_contract.dssp.ws.jaxb.dss.vr.CertificateStatusType;
import be.e_contract.dssp.ws.jaxb.dss.vr.CertificateValidityType;
import be.e_contract.dssp.ws.jaxb.dss.vr.DetailedSignatureReportType;
import be.e_contract.dssp.ws.jaxb.dss.vr.IndividualReportType;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignatureValidityType;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignedObjectIdentifierType;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignedPropertiesType;
import be.e_contract.dssp.ws.jaxb.dss.vr.SignedSignaturePropertiesType;
import be.e_contract.dssp.ws.jaxb.dss.vr.VerificationReportType;
import be.e_contract.dssp.ws.jaxb.dss.vr.VerificationResultType;
import be.e_contract.dssp.ws.jaxb.dssp.DeadlineType;
import be.e_contract.dssp.ws.jaxb.wssc.SecurityContextTokenType;
import be.e_contract.dssp.ws.jaxb.wst.BinarySecretType;
import be.e_contract.dssp.ws.jaxb.wst.EntropyType;
import be.e_contract.dssp.ws.jaxb.wst.RequestSecurityTokenResponseCollectionType;
import be.e_contract.dssp.ws.jaxb.wst.RequestSecurityTokenResponseType;
import be.e_contract.dssp.ws.jaxb.wst.RequestedSecurityTokenType;
import be.e_contract.dssp.ws.jaxb.xmldsig.DigestMethodType;
import be.e_contract.dssp.ws.jaxb.xmldsig.X509IssuerSerialType;
import be.e_contract.dssp.ws.jaxws.DigitalSignatureServicePortType;

@WebService(endpointInterface = "be.e_contract.dssp.ws.jaxws.DigitalSignatureServicePortType", wsdlLocation = "dssp-ws.wsdl", targetNamespace = "urn:be:e_contract:dssp:ws", serviceName = "DigitalSignatureService", portName = "DigitalSignatureServicePort")
@BindingType(SOAPBinding.SOAP12HTTP_BINDING)
@HandlerChain(file = "/test-ws-handlers.xml")
public class DigitalSignatureServiceTestPort implements DigitalSignatureServicePortType {

	private final static Logger LOGGER = LoggerFactory.getLogger(DigitalSignatureServiceTestPort.class);

	private final ObjectFactory objectFactory;

	private final be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory asyncObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.wst.ObjectFactory wstObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.wssc.ObjectFactory wsscObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory vrObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory dsspObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.localsig.ObjectFactory localsigObjectFactory;

	private final be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory dsObjectFactory;

	private final DatatypeFactory datatypeFactory;

	private boolean useAttachments;

	@Resource
	private WebServiceContext webServiceContext;

	private boolean receivedAttachment;

	public void reset() {
		this.receivedAttachment = false;
	}

	public boolean hasReceivedAttachment() {
		return this.receivedAttachment;
	}

	public DigitalSignatureServiceTestPort() {
		this.objectFactory = new ObjectFactory();
		this.asyncObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.async.ObjectFactory();
		this.wstObjectFactory = new be.e_contract.dssp.ws.jaxb.wst.ObjectFactory();
		this.wsscObjectFactory = new be.e_contract.dssp.ws.jaxb.wssc.ObjectFactory();
		this.vrObjectFactory = new be.e_contract.dssp.ws.jaxb.dss.vr.ObjectFactory();
		this.xmldsigObjectFactory = new be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory();
		this.dsspObjectFactory = new be.e_contract.dssp.ws.jaxb.dssp.ObjectFactory();
		this.localsigObjectFactory = new be.e_contract.dssp.ws.jaxb.localsig.ObjectFactory();
		this.dsObjectFactory = new be.e_contract.dssp.ws.jaxb.xmldsig.ObjectFactory();
		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException("datatype factory error: " + e.getMessage(), e);
		}
	}

	public void setUseAttachments(boolean useAttachments) {
		this.useAttachments = useAttachments;
	}

	@Override
	public ResponseBaseType verify(VerifyRequest verifyRequest) {
		ResponseBaseType response = this.objectFactory.createResponseBaseType();

		response.setProfile(DigitalSignatureServiceConstants.PROFILE);
		Result result = this.objectFactory.createResult();
		response.setResult(result);
		result.setResultMajor(DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR);

		AnyType optionalOutputs = this.objectFactory.createAnyType();
		response.setOptionalOutputs(optionalOutputs);
		VerificationReportType verificationReport = this.vrObjectFactory.createVerificationReportType();
		optionalOutputs.getAny().add(this.vrObjectFactory.createVerificationReport(verificationReport));

		DeadlineType timeStampRenewalDeadline = this.dsspObjectFactory.createDeadlineType();
		GregorianCalendar beforeGregorianCalendar = new GregorianCalendar();
		beforeGregorianCalendar.setTime(new Date());
		beforeGregorianCalendar.setTimeZone(TimeZone.getTimeZone("UTC"));
		XMLGregorianCalendar beforeXMLGregorianCalendar = this.datatypeFactory
				.newXMLGregorianCalendar(beforeGregorianCalendar);
		timeStampRenewalDeadline.setBefore(beforeXMLGregorianCalendar);
		optionalOutputs.getAny().add(this.dsspObjectFactory.createTimeStampRenewal(timeStampRenewalDeadline));

		IndividualReportType individualReport = this.vrObjectFactory.createIndividualReportType();
		verificationReport.getIndividualReport().add(individualReport);
		individualReport.setResult(result);
		SignedObjectIdentifierType signedObjectIdentifier = this.vrObjectFactory.createSignedObjectIdentifierType();
		individualReport.setSignedObjectIdentifier(signedObjectIdentifier);
		SignedPropertiesType signedProperties = this.vrObjectFactory.createSignedPropertiesType();
		signedObjectIdentifier.setSignedProperties(signedProperties);
		SignedSignaturePropertiesType signedSignatureProperties = this.vrObjectFactory
				.createSignedSignaturePropertiesType();
		signedProperties.setSignedSignatureProperties(signedSignatureProperties);
		GregorianCalendar signingTimeGregorianCalendar = new GregorianCalendar();
		signingTimeGregorianCalendar.setTime(new Date());
		signingTimeGregorianCalendar.setTimeZone(TimeZone.getTimeZone("UTC"));
		XMLGregorianCalendar signingTimeXMLGregorianCalendar = this.datatypeFactory
				.newXMLGregorianCalendar(signingTimeGregorianCalendar);
		signedSignatureProperties.setSigningTime(signingTimeXMLGregorianCalendar);

		AnyType details = this.objectFactory.createAnyType();
		individualReport.setDetails(details);
		DetailedSignatureReportType detailedSignatureReport = this.vrObjectFactory.createDetailedSignatureReportType();
		details.getAny().add(this.vrObjectFactory.createDetailedSignatureReport(detailedSignatureReport));

		VerificationResultType formatOKVerificationResult = this.vrObjectFactory.createVerificationResultType();
		formatOKVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);
		detailedSignatureReport.setFormatOK(formatOKVerificationResult);

		SignatureValidityType signatureOkSignatureValidity = this.vrObjectFactory.createSignatureValidityType();
		detailedSignatureReport.setSignatureOK(signatureOkSignatureValidity);
		VerificationResultType sigMathOkVerificationResult = this.vrObjectFactory.createVerificationResultType();
		signatureOkSignatureValidity.setSigMathOK(sigMathOkVerificationResult);
		sigMathOkVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);

		CertificatePathValidityType certificatePathValidity = this.vrObjectFactory.createCertificatePathValidityType();
		detailedSignatureReport.setCertificatePathValidity(certificatePathValidity);

		VerificationResultType certPathVerificationResult = this.vrObjectFactory.createVerificationResultType();
		certPathVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);
		certificatePathValidity.setPathValiditySummary(certPathVerificationResult);

		X509IssuerSerialType certificateIdentifier = this.xmldsigObjectFactory.createX509IssuerSerialType();
		certificatePathValidity.setCertificateIdentifier(certificateIdentifier);
		certificateIdentifier.setX509IssuerName("CN=Issuer");
		certificateIdentifier.setX509SerialNumber(BigInteger.ONE);

		CertificatePathValidityVerificationDetailType certificatePathValidityVerificationDetail = this.vrObjectFactory
				.createCertificatePathValidityVerificationDetailType();
		certificatePathValidity.setPathValidityDetail(certificatePathValidityVerificationDetail);
		CertificateValidityType certificateValidity = this.vrObjectFactory.createCertificateValidityType();
		certificatePathValidityVerificationDetail.getCertificateValidity().add(certificateValidity);
		certificateValidity.setCertificateIdentifier(certificateIdentifier);
		certificateValidity.setSubject("CN=Subject");

		VerificationResultType chainingOkVerificationResult = this.vrObjectFactory.createVerificationResultType();
		certificateValidity.setChainingOK(chainingOkVerificationResult);
		chainingOkVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);

		VerificationResultType validityPeriodOkVerificationResult = this.vrObjectFactory.createVerificationResultType();
		certificateValidity.setValidityPeriodOK(validityPeriodOkVerificationResult);
		validityPeriodOkVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);

		VerificationResultType extensionsOkVerificationResult = this.vrObjectFactory.createVerificationResultType();
		certificateValidity.setExtensionsOK(extensionsOkVerificationResult);
		extensionsOkVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);

		byte[] encodedCertificate;
		try {
			encodedCertificate = IOUtils
					.toByteArray(DigitalSignatureServiceTestPort.class.getResource("/fcorneli.der"));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		certificateValidity.setCertificateValue(encodedCertificate);

		certificateValidity.setSignatureOK(signatureOkSignatureValidity);

		CertificateStatusType certificateStatus = this.vrObjectFactory.createCertificateStatusType();
		certificateValidity.setCertificateStatus(certificateStatus);
		VerificationResultType certStatusOkVerificationResult = this.vrObjectFactory.createVerificationResultType();
		certificateStatus.setCertStatusOK(certStatusOkVerificationResult);
		certStatusOkVerificationResult.setResultMajor(DigitalSignatureServiceConstants.VR_RESULT_MAJOR_VALID);

		return response;
	}

	@Override
	public SignResponse sign(SignRequest signRequest) {
		MessageContext messageContext = this.webServiceContext.getMessageContext();
		Map<String, DataHandler> attachments = (Map<String, DataHandler>) messageContext
				.get(MessageContext.INBOUND_MESSAGE_ATTACHMENTS);
		LOGGER.debug("attachments: {}", attachments.keySet());
		if (!attachments.isEmpty()) {
			receivedAttachment = true;
		}

		if (signRequest.getProfile().equals(DigitalSignatureServiceConstants.ADES_A_PROFILE)) {
			SignResponse signResponse = this.objectFactory.createSignResponse();
			signResponse.setProfile(DigitalSignatureServiceConstants.ADES_A_PROFILE);

			Result result = this.objectFactory.createResult();
			signResponse.setResult(result);
			result.setResultMajor(DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR);

			AnyType optionalOutputs = this.objectFactory.createAnyType();
			signResponse.setOptionalOutputs(optionalOutputs);

			DocumentWithSignature documentWithSignature = this.objectFactory.createDocumentWithSignature();
			optionalOutputs.getAny().add(documentWithSignature);
			DocumentType document = this.objectFactory.createDocumentType();
			documentWithSignature.setDocument(document);

			if (false == this.useAttachments) {
				Base64Data base64Data = this.objectFactory.createBase64Data();
				document.setBase64Data(base64Data);
				base64Data.setMimeType("text/plain");
				base64Data.setValue("signed document".getBytes());
			} else {
				AttachmentReferenceType attachmentReference = this.objectFactory.createAttachmentReferenceType();
				document.setAttachmentReference(attachmentReference);
				attachmentReference.setMimeType("text/plain");
				String contentId = UUID.randomUUID().toString();
				attachmentReference.setAttRefURI("cid:" + contentId);
				addAttachment("text/plain", contentId, "hello world".getBytes());
			}

			return signResponse;
		}

		if (signRequest.getProfile().equals(DigitalSignatureServiceConstants.ESEAL_PROFILE)) {
			SignResponse signResponse = this.objectFactory.createSignResponse();
			signResponse.setProfile(DigitalSignatureServiceConstants.ESEAL_PROFILE);

			Result result = this.objectFactory.createResult();
			signResponse.setResult(result);
			result.setResultMajor(DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR);

			AnyType optionalOutputs = this.objectFactory.createAnyType();
			signResponse.setOptionalOutputs(optionalOutputs);

			DocumentWithSignature documentWithSignature = this.objectFactory.createDocumentWithSignature();
			optionalOutputs.getAny().add(documentWithSignature);
			DocumentType document = this.objectFactory.createDocumentType();
			documentWithSignature.setDocument(document);

			if (false == this.useAttachments) {
				Base64Data base64Data = this.objectFactory.createBase64Data();
				document.setBase64Data(base64Data);
				base64Data.setMimeType("text/plain");
				base64Data.setValue("signed document".getBytes());
			} else {
				AttachmentReferenceType attachmentReference = this.objectFactory.createAttachmentReferenceType();
				document.setAttachmentReference(attachmentReference);
				attachmentReference.setMimeType("text/plain");
				String contentId = UUID.randomUUID().toString();
				attachmentReference.setAttRefURI("cid:" + contentId);
				addAttachment("text/plain", contentId, "hello world".getBytes());
			}

			return signResponse;
		}

		if (signRequest.getProfile().equals(DigitalSignatureServiceConstants.LOCALSIG_PROFILE)) {
			SignResponse signResponse = this.objectFactory.createSignResponse();
			signResponse.setProfile(DigitalSignatureServiceConstants.LOCALSIG_PROFILE);

			boolean secondPhase = false;
			AnyType optionalInputs = signRequest.getOptionalInputs();
			for (Object optionalInput : optionalInputs.getAny()) {
				LOGGER.debug("optional input: {}", optionalInput.getClass());
				if (optionalInput instanceof JAXBElement) {
					JAXBElement optionalInputElement = (JAXBElement) optionalInput;
					if (optionalInputElement.getName().equals(DigitalSignatureServiceConstants.CORRELATION_ID_QNAME)) {
						secondPhase = true;
					}
				}
			}

			Result result = this.objectFactory.createResult();
			signResponse.setResult(result);
			result.setResultMajor(DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR);

			AnyType optionalOutputs = this.objectFactory.createAnyType();
			signResponse.setOptionalOutputs(optionalOutputs);

			if (secondPhase) {
				result.setResultMinor("urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments");

				DocumentWithSignature documentWithSignature = this.objectFactory.createDocumentWithSignature();
				optionalOutputs.getAny().add(documentWithSignature);
				DocumentType document = this.objectFactory.createDocumentType();
				documentWithSignature.setDocument(document);

				Base64Data base64Data = this.objectFactory.createBase64Data();
				document.setBase64Data(base64Data);
				base64Data.setMimeType("text/plain");
				base64Data.setValue("signed document".getBytes());
			} else {
				result.setResultMinor(DigitalSignatureServiceConstants.DOCUMENT_HASH_RESULT_MINOR);

				JAXBElement<String> correlationId = this.localsigObjectFactory
						.createCorrelationID(UUID.randomUUID().toString());
				optionalOutputs.getAny().add(correlationId);

				DocumentHash documentHash = this.objectFactory.createDocumentHash();
				DigestMethodType digestMethod = this.dsObjectFactory.createDigestMethodType();
				digestMethod.setAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");
				documentHash.setDigestMethod(digestMethod);
				documentHash.setDigestValue("digest value".getBytes());
				optionalOutputs.getAny().add(documentHash);
			}

			return signResponse;
		}

		SignResponse signResponse = this.objectFactory.createSignResponse();

		Result result = this.objectFactory.createResult();
		signResponse.setResult(result);
		result.setResultMajor(DigitalSignatureServiceConstants.PENDING_RESULT_MAJOR);

		AnyType optionalOutputs = this.objectFactory.createAnyType();
		signResponse.setOptionalOutputs(optionalOutputs);

		optionalOutputs.getAny().add(this.asyncObjectFactory.createResponseID("response identifier"));

		RequestSecurityTokenResponseCollectionType requestSecurityTokenResponseCollection = this.wstObjectFactory
				.createRequestSecurityTokenResponseCollectionType();
		optionalOutputs.getAny().add(this.wstObjectFactory
				.createRequestSecurityTokenResponseCollection(requestSecurityTokenResponseCollection));
		RequestSecurityTokenResponseType requestSecurityTokenResponse = this.wstObjectFactory
				.createRequestSecurityTokenResponseType();
		requestSecurityTokenResponseCollection.getRequestSecurityTokenResponse().add(requestSecurityTokenResponse);
		RequestedSecurityTokenType requestedSecurityToken = this.wstObjectFactory.createRequestedSecurityTokenType();
		requestSecurityTokenResponse.getAny()
				.add(this.wstObjectFactory.createRequestedSecurityToken(requestedSecurityToken));
		SecurityContextTokenType securityContextToken = this.wsscObjectFactory.createSecurityContextTokenType();
		requestedSecurityToken.setAny(this.wsscObjectFactory.createSecurityContextToken(securityContextToken));
		securityContextToken.setId("token-reference");
		securityContextToken.getAny().add(this.wsscObjectFactory.createIdentifier("token-identifier"));
		EntropyType entropy = this.wstObjectFactory.createEntropyType();
		requestSecurityTokenResponse.getAny().add(this.wstObjectFactory.createEntropy(entropy));
		BinarySecretType binarySecret = this.wstObjectFactory.createBinarySecretType();
		entropy.getAny().add(this.wstObjectFactory.createBinarySecret(binarySecret));
		byte[] nonce = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(nonce);
		binarySecret.setValue(nonce);

		return signResponse;
	}

	@Override
	public SignResponse pendingRequest(PendingRequest pendingRequest) {
		SignResponse signResponse = this.objectFactory.createSignResponse();

		Result result = this.objectFactory.createResult();
		signResponse.setResult(result);
		result.setResultMajor(DigitalSignatureServiceConstants.SUCCESS_RESULT_MAJOR);

		AnyType optionalOutputs = this.objectFactory.createAnyType();
		signResponse.setOptionalOutputs(optionalOutputs);

		DocumentWithSignature documentWithSignature = this.objectFactory.createDocumentWithSignature();
		optionalOutputs.getAny().add(documentWithSignature);
		DocumentType document = this.objectFactory.createDocumentType();
		documentWithSignature.setDocument(document);

		if (false == this.useAttachments) {
			Base64Data base64Data = this.objectFactory.createBase64Data();
			document.setBase64Data(base64Data);
			base64Data.setMimeType("text/plain");
			base64Data.setValue("signed document".getBytes());
		} else {
			AttachmentReferenceType attachmentReference = this.objectFactory.createAttachmentReferenceType();
			document.setAttachmentReference(attachmentReference);
			attachmentReference.setMimeType("text/plain");
			String contentId = UUID.randomUUID().toString();
			attachmentReference.setAttRefURI("cid:" + contentId);
			addAttachment("text/plain", contentId, "hello world".getBytes());
		}

		return signResponse;
	}

	private String addAttachment(String mimetype, String contentId, byte[] data) {
		LOGGER.debug("adding attachment: {}", contentId);
		DataSource dataSource = new ByteArrayDataSource(data, mimetype);
		DataHandler dataHandler = new DataHandler(dataSource);
		MessageContext messageContext = this.webServiceContext.getMessageContext();

		Map<String, DataHandler> outputMessageAttachments = (Map<String, DataHandler>) messageContext
				.get(MessageContext.OUTBOUND_MESSAGE_ATTACHMENTS);
		outputMessageAttachments.put(contentId, dataHandler);
		messageContext.put(MessageContext.OUTBOUND_MESSAGE_ATTACHMENTS, outputMessageAttachments);

		return contentId;
	}
}
