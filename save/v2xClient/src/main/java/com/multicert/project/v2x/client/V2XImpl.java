package com.multicert.project.v2x.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.EccP256CurvePoint;
import com.multicert.v2x.datastructures.base.GeographicRegion;
import com.multicert.v2x.datastructures.base.EccP256CurvePoint.EccP256CurvePointTypes;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.base.ValidityPeriod;
import com.multicert.v2x.generators.certificaterequest.EnrollmentRequestGenerator;
import com.multicert.v2x.generators.message.SecuredDataGenerator;

public class V2XImpl implements V2X {
	
	private CryptoHelper cryptoHelper;
	private EnrollmentRequestGenerator eRequestGenerator;
	private SecuredDataGenerator securedDataGenr;
	private EnrollmentRequestGenerator ecRequestenerator;
	
	public V2XImpl() throws Exception {
		cryptoHelper = new CryptoHelper("BC");
		eRequestGenerator = new EnrollmentRequestGenerator(cryptoHelper, false);	
	}
	
	@Override
	public KeyPair genKeyPair(AlgorithmType alg) throws Exception
	{
		return cryptoHelper.genKeyPair(alg);
	}
	
	
	@Override
	public PublicVerificationKey buildVerificationKey(PublicKey publicKey, AlgorithmType alg) throws IllegalArgumentException, InvalidKeySpecException, IOException  
	{
		EccP256CurvePoint point = (EccP256CurvePoint)cryptoHelper.publicKeyToEccPoint(alg, EccP256CurvePointTypes.UNCOMPRESSED, publicKey);
		return new PublicVerificationKey(cryptoHelper.getVerificationKeyType(alg),point);
	
	}
	
	@Override
	public EtsiTs103097Data genEcRequest(String itsID, KeyPair canonicalKeys,  AlgorithmType canonicalAlgorithm, KeyPair verificationKeys, AlgorithmType verificationAlgorithm,
            ValidityPeriod validityPeriod, GeographicRegion geographicRegion,
            int assuranceLevel, int confidenceLevel, EtsiTs103097Certificate EnrollmentAuthorityCertificate) throws Exception, GeneralSecurityException
	{
		return ecRequestenerator.generateEcRequest(itsID, canonicalKeys, canonicalAlgorithm, verificationKeys, verificationAlgorithm, validityPeriod, geographicRegion, assuranceLevel, confidenceLevel, EnrollmentAuthorityCertificate);
	}


}
