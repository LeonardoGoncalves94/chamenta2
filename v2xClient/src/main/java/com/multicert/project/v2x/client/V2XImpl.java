package com.multicert.project.v2x.client;

import java.security.KeyPair;

import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.generators.certificaterequest.EnrollmentRequestGenerator;

public class V2XImpl implements V2X {
	
	private CryptoHelper cryptoHelper;
	private EnrollmentRequestGenerator eRequestGenerator;
	
	public V2XImpl() throws Exception {
		cryptoHelper = new CryptoHelper("BC");
		eRequestGenerator = new EnrollmentRequestGenerator(cryptoHelper, false);	
	}
	
	@Override
	public KeyPair genKeyPair(AlgorithmType alg) throws Exception
	{
		return cryptoHelper.genKeyPair(alg);
	}
}
