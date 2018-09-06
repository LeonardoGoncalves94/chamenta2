package com.multicert.project.v2x.client;

import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.generators.certificaterequest.EnrollmentRequestGenerator;

public class V2XImpl {
	
	private CryptoHelper cryptoHelper;
	private EnrollmentRequestGenerator eRequestGenerator;
	
	public V2XImpl() throws Exception {
		cryptoHelper = new CryptoHelper("BC");
		eRequestGenerator = new EnrollmentRequestGenerator(cryptoHelper, false);	
	}
}
