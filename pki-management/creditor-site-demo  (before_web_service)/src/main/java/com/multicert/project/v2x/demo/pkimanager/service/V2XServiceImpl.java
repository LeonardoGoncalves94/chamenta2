package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.demo.pkimanager.DemoApplication;
import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Certificate;
import com.multicert.project.v2x.demo.pkimanager.model.Key;
import com.multicert.project.v2x.demo.pkimanager.model.Region;
import com.multicert.project.v2x.demo.pkimanager.model.Role;
import com.multicert.project.v2x.demo.pkimanager.model.User;
import com.multicert.project.v2x.demo.pkimanager.repository.RoleRepository;
import com.multicert.project.v2x.demo.pkimanager.repository.UserRepository;
import com.multicert.v2x.IdentifiedRegions.Countries;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.BasePublicEncryptionKey.BasePublicEncryptionKeyTypes;
import com.multicert.v2x.datastructures.base.CountryOnly;
import com.multicert.v2x.datastructures.base.Duration.DurationTypes;
import com.multicert.v2x.datastructures.base.GeographicRegion;
import com.multicert.v2x.datastructures.base.IdentifiedRegion;
import com.multicert.v2x.datastructures.base.Psid;
import com.multicert.v2x.datastructures.base.PsidSspRange;
import com.multicert.v2x.datastructures.base.SequenceOfIdentifiedRegion;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.base.SspRange;
import com.multicert.v2x.datastructures.base.SymmAlgorithm;
import com.multicert.v2x.datastructures.base.ValidityPeriod;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.generators.certificate.CACertGenerator;


@Service("V2XService")
public class V2XServiceImpl implements V2XService{

	private CryptoHelper cryptoHelper;
	private CACertGenerator caCertGenerator;
	
	public V2XServiceImpl() throws Exception {
		cryptoHelper = new CryptoHelper("BC");
		caCertGenerator = new CACertGenerator(cryptoHelper, false);
		
	}
	
	@Override
	public void genKeyPair(String alias, String algorithm) throws Exception {
		
		cryptoHelper.genKeyPair(getCurveType(algorithm), alias);
		cryptoHelper.printKeyStore();
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
			KeyPair subjectSigKeys = cryptoHelper.getKeyPair(signatureKey.getAlias());
			
			BasePublicEncryptionKeyTypes encAlgorithm = null;	
			PublicKey subjectEncKey = null;
			SymmAlgorithm symmAlgorithm = null;
			
			if(encryptionKey != null)
			{
				encAlgorithm = getEncryptionType(encryptionKey.getAlgorithm());
				subjectEncKey = cryptoHelper.getKeyPair(encryptionKey.getAlias()).getPublic();
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
			KeyPair issuerSigKeys = cryptoHelper.getKeyPair(issuerKey.getAlias());
			EtsiTs103097Certificate issuerCertificate = new EtsiTs103097Certificate(issuer.getCertificate().getEncoded());
			
			Key signatureKey = subject.getSignatureKey(); 
			Key encryptionKey = subject.getEncryptionKey();
			Signature.SignatureTypes sigAlgorithm = getSignatureType(signatureKey.getAlgorithm());
			KeyPair subjectSigKeys = cryptoHelper.getKeyPair(signatureKey.getAlias());
			
			BasePublicEncryptionKeyTypes encAlgorithm = null;	
			PublicKey subjectEncKey = null;
			SymmAlgorithm symmAlgorithm = null;
			
			if(encryptionKey != null)
			{
				encAlgorithm = getEncryptionType(encryptionKey.getAlgorithm());
				subjectEncKey = cryptoHelper.getKeyPair(encryptionKey.getAlias()).getPublic();
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
	 * Help method that converts a known string that represents an  algorithm into an encryption algorithm 
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

}