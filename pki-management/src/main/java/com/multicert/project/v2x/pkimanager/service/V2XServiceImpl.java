package com.multicert.project.v2x.pkimanager.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.pkimanager.DemoApplication;
import com.multicert.project.v2x.pkimanager.JavaKeyStore;
import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.Certificate;
import com.multicert.project.v2x.pkimanager.model.Key;
import com.multicert.project.v2x.pkimanager.model.Region;
import com.multicert.project.v2x.pkimanager.model.Role;
import com.multicert.project.v2x.pkimanager.model.User;
import com.multicert.project.v2x.pkimanager.repository.RoleRepository;
import com.multicert.project.v2x.pkimanager.repository.UserRepository;
import com.multicert.v2x.IdentifiedRegions.Countries;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.asn1.coer.COEROctetString;
import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.cryptography.DecryptionException;
import com.multicert.v2x.cryptography.ImcompleteRequestException;
import com.multicert.v2x.cryptography.IncorrectRecipientException;
import com.multicert.v2x.cryptography.InvalidSignatureException;
import com.multicert.v2x.cryptography.UnknownItsException;
import com.multicert.v2x.datastructures.base.BasePublicEncryptionKey.BasePublicEncryptionKeyTypes;
import com.multicert.v2x.datastructures.base.CountryOnly;
import com.multicert.v2x.datastructures.base.Duration.DurationTypes;
import com.multicert.v2x.datastructures.base.EccP256CurvePoint;
import com.multicert.v2x.datastructures.base.GeographicRegion;
import com.multicert.v2x.datastructures.base.IdentifiedRegion;
import com.multicert.v2x.datastructures.base.Psid;
import com.multicert.v2x.datastructures.base.PsidSspRange;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.base.SequenceOfIdentifiedRegion;
import com.multicert.v2x.datastructures.base.SequenceOfPsidSsp;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.base.SspRange;
import com.multicert.v2x.datastructures.base.SubjectAssurance;
import com.multicert.v2x.datastructures.base.SymmAlgorithm;
import com.multicert.v2x.datastructures.base.ValidityPeriod;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.datastructures.certificate.SequenceOfPsidGroupPermissions;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.EnrollmentResonseCode;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.InnerEcRequest;
import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;
import com.multicert.v2x.generators.certificate.CACertGenerator;
import com.multicert.v2x.generators.certificate.EnrollmentCredentiaGenerator;
import com.multicert.v2x.generators.certificaterequest.EnrollmentResponseGenerator;
import com.multicert.v2x.generators.message.SecuredDataGenerator;


@Service("V2XService")
public class V2XServiceImpl implements V2XService{

	private CryptoHelper cryptoHelper;
	private CACertGenerator caCertGenerator;
	
	private EnrollmentResponseGenerator eResponseGenerator;
	private EnrollmentCredentiaGenerator enrollmentCertGenerator;
	
	public V2XServiceImpl() throws Exception {
		cryptoHelper = new CryptoHelper("BC");
		caCertGenerator = new CACertGenerator(cryptoHelper, false);
		eResponseGenerator = new EnrollmentResponseGenerator(cryptoHelper, false);
		enrollmentCertGenerator = new EnrollmentCredentiaGenerator(cryptoHelper, false);
		
	}
	
	@Override
	public KeyPair genKeyPair( String algorithm) throws Exception {
		
		return cryptoHelper.genKeyPair(getCurveType(algorithm));
	}
	

	@Override
	public byte[] genRootCertificate(Certificate rootcertificate) throws Exception {
			
		try {
			CA subject = rootcertificate.getSubject();
			
			String hostname = subject.getCaName();
			ValidityPeriod validityPeriod = new ValidityPeriod(new Date(),DurationTypes.YEARS, rootcertificate.getValidity());	
			GeographicRegion geographicRegion = getGeographicRegion(rootcertificate.getRegions());
			
			
			
			Key signatureKey = subject.getSignatureKey(); 
			Key encryptionKey = subject.getEncryptionKey();
			
			Signature.SignatureTypes sigAlgorithm = getSignatureType(signatureKey.getAlgorithm());
			KeyPair subjectSigKeys = JavaKeyStore.getKeyPair(signatureKey.getAlias());
			
			BasePublicEncryptionKeyTypes encAlgorithm = null;	
			PublicKey subjectEncKey = null;
			SymmAlgorithm symmAlgorithm = null;
			
			if(encryptionKey != null)
			{
				encAlgorithm = getEncryptionType(encryptionKey.getAlgorithm());
				subjectEncKey = JavaKeyStore.getKeyPair(encryptionKey.getAlias()).getPublic();
				symmAlgorithm = SymmAlgorithm.AES_128_CCM;
			}
			
			EtsiTs103097Certificate rootCertificate = caCertGenerator.generateRootCA(hostname, validityPeriod, geographicRegion, 
					rootcertificate.getAssurance().intValue(), rootcertificate.getConfidence().intValue(), 
					rootcertificate.getMinChain().intValue(), rootcertificate.getChainRange().intValue(), sigAlgorithm, 
					subjectSigKeys, symmAlgorithm, encAlgorithm, subjectEncKey);
			return rootCertificate.getEncoded();
			
		} catch(Exception e) {
			e.printStackTrace();
			throw new Exception ("Error generating certificate");
		}
	}

	@Override
	public byte[] genSubCertificate(Certificate subCertificate ) throws Exception {
		
		try {
			CA issuer = subCertificate.getIssuer();
			
			CA subject = subCertificate.getSubject();
			String caType = subject.getCaType();
			
			String hostname = subject.getCaName();
			ValidityPeriod validityPeriod = new ValidityPeriod(new Date(),DurationTypes.YEARS, subCertificate.getValidity());	
			GeographicRegion geographicRegion = getGeographicRegion(subCertificate.getRegions());
			
	        PsidSspRange[] subjectPerms = new PsidSspRange[1];
	        subjectPerms[0] = new PsidSspRange(new Psid(subCertificate.getPsId()), new SspRange(SspRange.SspRangeTypes.ALL, null));
	        int assurance = subCertificate.getAssurance().intValue();
	        int confidence = subCertificate.getConfidence().intValue();
	        int minChainDepth = subCertificate.getMinChain().intValue();
	        int chainDepthRange = subCertificate.getChainRange().intValue();
	       
			
			Key issuerKey = issuer.getSignatureKey();
			KeyPair issuerSigKeys = JavaKeyStore.getKeyPair(issuerKey.getAlias());
			EtsiTs103097Certificate issuerCertificate = new EtsiTs103097Certificate(issuer.getCertificate().getEncoded());
			
			Key signatureKey = subject.getSignatureKey(); 
			Key encryptionKey = subject.getEncryptionKey();
			Signature.SignatureTypes sigAlgorithm = getSignatureType(signatureKey.getAlgorithm());
			KeyPair subjectSigKeys = JavaKeyStore.getKeyPair(signatureKey.getAlias());
			
			BasePublicEncryptionKeyTypes encAlgorithm = null;	
			PublicKey subjectEncKey = null;
			SymmAlgorithm symmAlgorithm = null;
			
			if(encryptionKey != null)
			{
				encAlgorithm = getEncryptionType(encryptionKey.getAlgorithm());
				subjectEncKey = JavaKeyStore.getKeyPair(encryptionKey.getAlias()).getPublic();
				symmAlgorithm = SymmAlgorithm.AES_128_CCM;
			}
			
			if(caType.equals("Enrollment")) 
			{
				EtsiTs103097Certificate enrollmentCaCert = caCertGenerator.generateEnrollmentCa(hostname,validityPeriod,geographicRegion,
						subjectPerms,assurance,confidence,minChainDepth,chainDepthRange,sigAlgorithm,subjectSigKeys.getPublic(),
						issuerCertificate,issuerSigKeys,symmAlgorithm,encAlgorithm,subjectEncKey);
				return enrollmentCaCert.getEncoded();
			}
			if (caType.equals("Authorization"))
			{
				EtsiTs103097Certificate authorizationCaCert = caCertGenerator.generateAuthorizationAuthority(hostname,validityPeriod,geographicRegion,
						subjectPerms,assurance,confidence,minChainDepth,chainDepthRange,sigAlgorithm,subjectSigKeys.getPublic(),
						issuerCertificate,issuerSigKeys,symmAlgorithm,encAlgorithm,subjectEncKey);
				return authorizationCaCert.getEncoded();
			}
			 throw new IOException("Error generation Sub CA certificate: CA type is unknown");
			
		} catch(Exception e) {
			e.printStackTrace();
			throw new Exception ("Error generating certificate");
		}
		
	}
	
	@Override
	public EtsiTs103097Data processEcRequest(byte[] encryptedRequest, Certificate destinationCertificate, Key decriptionPair, PublicKey canonicalKey, Key sigKeyPair) throws Exception 
	{
		
		SecuredDataGenerator securedDataGenerator = new SecuredDataGenerator(cryptoHelper);
		
		EtsiTs103097Certificate destCert = new EtsiTs103097Certificate(destinationCertificate.getEncoded());
		PrivateKey decryptionKey = JavaKeyStore.getKeyPair(decriptionPair.getAlias()).getPrivate();
		KeyPair signatureKeys = JavaKeyStore.getKeyPair(sigKeyPair.getAlias());
		AlgorithmType sigAlg = getSignatureType(decriptionPair.getAlgorithm());
		byte[] decyptedBytes;
		
		decyptedBytes = securedDataGenerator.decryptEncryptedData(new EtsiTs103097Data(encryptedRequest),destCert ,decryptionKey); //if the CA cant decrypt the request, it cannot encrypt the response. The RA is notified of this.
		SecretKey sharedKey = securedDataGenerator.getSharedKey();
		
		EtsiTs103097Data decryptedRequest = new EtsiTs103097Data(decyptedBytes);
		
		EnrollmentResonseCode responseCode = EnrollmentResonseCode.OK;
		try {
			securedDataGenerator.verifySignedRequest(decryptedRequest, canonicalKey);
		} catch (IllegalArgumentException | SignatureException | InvalidKeySpecException | ImcompleteRequestException
				| BadContentTypeException | InvalidSignatureException e) {
			e.printStackTrace();
			responseCode = exceptionToResponseCode(e);
			genResponse(decryptedRequest,sharedKey, responseCode, destCert, signatureKeys, sigAlg, securedDataGenerator);
			return null;
		}
		// in case the request was successfully decrypted and the vehicle's signature checks, we need to check if the requested attributes are plausible for this vehicle's profile
		responseCode = verifyRequestedSubjectAttributes();
		 return genResponse(decryptedRequest,sharedKey, responseCode, destCert, signatureKeys, sigAlg, securedDataGenerator);		
	}
	
	/**
	 * Dummy method that verifies the attributes that the vehicle is requesting
	 * @return response code OK if everything checks or DENIED_PERMISSIONS otherwise
	 */
	private EnrollmentResonseCode verifyRequestedSubjectAttributes() 
	{
		//TODO: make real verification of the attributes that the vehicle is requesting, i.e. validity period, region, app permissions etc
		return EnrollmentResonseCode.OK;
	
	}
	
	/**
	 * Method that generates a response to the vehicle (Only called when the CA is able to decrypt the original request)
	 * @param signedRequest 
	 * @param sharedKey
	 * @param responseCode
	 * @param destCert
	 * @param EAsigningKey
	 * @param signingAlgorithm
	 * @return
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 */
	private EtsiTs103097Data genResponse(EtsiTs103097Data signedRequest, SecretKey sharedKey, 
			EnrollmentResonseCode responseCode, EtsiTs103097Certificate EAcertificate, 
			KeyPair signatureKeys, AlgorithmType signingAlgorithm, SecuredDataGenerator securedDataGenerator) throws IOException, GeneralSecurityException
	{	
		if(responseCode != EnrollmentResonseCode.OK)
		{
			return eResponseGenerator.generateEcResponse(signedRequest, sharedKey, responseCode, null, EAcertificate, signatureKeys, signingAlgorithm); //negative response with an error code an no enrollment credential is returned
		}
		else
		{
			InnerEcRequest innerRequest = securedDataGenerator.getInnerEcRequest();
			EtsiTs103097Certificate enrollmentCredential =  genEnrollmentCredential(innerRequest, signingAlgorithm,EAcertificate, signatureKeys, securedDataGenerator);
			return eResponseGenerator.generateEcResponse(signedRequest, sharedKey, responseCode, enrollmentCredential, EAcertificate, signatureKeys, signingAlgorithm); //positive response with new enrollment credential is returned
		}
		
	}
	
	private EtsiTs103097Certificate genEnrollmentCredential(InnerEcRequest innerRequest,
			AlgorithmType signingAlgorithm, EtsiTs103097Certificate EAcertificate,
			KeyPair signatureKeys, SecuredDataGenerator securedDataGenerator) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, IOException
	{
		String itsId = innerRequest.getItsId();
		ValidityPeriod validityPeriod = innerRequest.getRequestedSubjectAttributes().getValidityPeriod();
		GeographicRegion validityRegion = innerRequest.getRequestedSubjectAttributes().getRegion();
		
		SubjectAssurance assurance = innerRequest.getRequestedSubjectAttributes().getAssuranceLevel();
		int assuranceLevel = assurance.getAssuranceLevel();
		int confidenceLevel = assurance.getConfidenceLevel();
		
		SequenceOfPsidSsp appPermissions = innerRequest.getRequestedSubjectAttributes().getAppPermissions();
		
		PublicKey vehicleVerificationKey = securedDataGenerator.getRequestPublicKey();
		
		return enrollmentCertGenerator.generateEnrollmentCredential(itsId,validityPeriod,validityRegion,assuranceLevel,confidenceLevel,signingAlgorithm, vehicleVerificationKey, EAcertificate, signatureKeys, null, null, null); //Encryption information is set to null
		
			
		
	}
	
	 
    
	
	@Override
	public PublicKey extractPublicKey(PublicVerificationKey verificationKey) throws InvalidKeySpecException {
		
		AlgorithmType alg = verificationKey.getType();
		EccP256CurvePoint curvePoint = (EccP256CurvePoint) verificationKey.getValue();
		return (PublicKey) cryptoHelper.eccPointToPublicKey(alg, curvePoint);
	}
	
	/**
	 * Help method that converts a known string that represents an algorithm into a signature algorithm 
	 * Used when generating a keyPair to specify the type of curve.
	 * @throws IOException 
	 */
	private Signature.SignatureTypes getCurveType (String alg) throws IOException {
		
		if(alg.equals("ECDSA-Nist" ) || alg.equals("ECIES-Nist")) {
			return Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;
		}
		if(alg.equals("ECDSA-Brainpool") || alg.equals("ECIES-Brainpool")){
			
			return Signature.SignatureTypes.ECDSA_BRAINPOOL_P256R1_SIGNATURE;
		}
		
		throw new IOException("Error geting curve type: specified algorithm does not exist");		
	}
	
	
	/**
	 * Help method that converts a known string that represents an algorithm into a signature algorithm 
	 * Used when generating a certificate to specify the algorithm of the encryption key
	 * @throws IOException 
	 */
	private Signature.SignatureTypes getSignatureType (String alg) throws IOException {
		
		if(alg.equals("ECDSA-Nist" )) {
			return Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;
		}
		if(alg.equals("ECDSA-Brainpool")){
			
			return Signature.SignatureTypes.ECDSA_BRAINPOOL_P256R1_SIGNATURE;
		}
		
		throw new IOException("Error geting signature algorithm: specified algorithm does not exist");
			
	}
	
	/**
	 * Help method that converts a known string that represents an algorithm into an encryption algorithm object
	 * Used when generating a certificate to specify the algorithm of the encryption key
	 * @throws IOException 
	 */
	private BasePublicEncryptionKeyTypes getEncryptionType (String alg) throws IOException {
		
		if(alg.equals("ECIES-Nist")) {
			return BasePublicEncryptionKeyTypes.ECIES_NIST_P256;
		}
		if(alg.equals("ECIES-Brainpool")){
			
			return BasePublicEncryptionKeyTypes.ECIES_BRAINPOOL_P256r1;
		}
		
		throw new IOException("Error geting encryption algorithm: specified algorithm does not exist");
			
	}
	
	private GeographicRegion getGeographicRegion(List <Region> regions) {
		
		int size = regions.size();
		IdentifiedRegion[] identifiedRegions = new IdentifiedRegion[size];
		
		for(int i = 0; i < size; i++) {
			
			IdentifiedRegion identifiedRegion = new IdentifiedRegion(new CountryOnly(regions.get(i).getRegionNumber()));
            identifiedRegions[i] = identifiedRegion;
		}
		 SequenceOfIdentifiedRegion sequenceOfIdentifiedRegion = new SequenceOfIdentifiedRegion(identifiedRegions);
		 return new GeographicRegion(sequenceOfIdentifiedRegion);
	}
	
	
	/**
	 * Method that converts a known enrollment validation exception into an EnrollmentResonseCode to be part of the Enrollment response
	 */
	private EnrollmentResonseCode exceptionToResponseCode (Exception e)
	{
			if(e instanceof BadContentTypeException) {
				e.printStackTrace();
				return EnrollmentResonseCode.BAD_CONTENT_TYPE;
			}
			if(e instanceof DecryptionException) {
				e.printStackTrace();
				return EnrollmentResonseCode.DECRYPTION_FAILED;
			}
			if(e instanceof ImcompleteRequestException) {
				e.printStackTrace();
			return EnrollmentResonseCode.INCOMPLETE_REQUEST;
			}
		
			if(e instanceof InvalidSignatureException) {
				e.printStackTrace();
				return EnrollmentResonseCode.INVALID_SIGNATURE;
			}
			if(e instanceof UnknownItsException) {
				e.printStackTrace();
				return EnrollmentResonseCode.UNKNOWN_ITS;
			}
			return EnrollmentResonseCode.DENIED_REQUEST;
	}	
}
