package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.demo.pkimanager.DemoApplication;
import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Region;
import com.multicert.project.v2x.demo.pkimanager.model.Role;
import com.multicert.project.v2x.demo.pkimanager.model.User;
import com.multicert.project.v2x.demo.pkimanager.repository.RoleRepository;
import com.multicert.project.v2x.demo.pkimanager.repository.UserRepository;
import com.multicert.v2x.IdentifiedRegions.Countries;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.CountryOnly;
import com.multicert.v2x.datastructures.base.Duration.DurationTypes;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.base.ValidityPeriod;
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
	public void genKey(String alias, String algorithm) throws Exception {
		
		cryptoHelper.genKeyPair(getSignatureType(algorithm), alias);
		cryptoHelper.printKeyStore();
	}

	@Override
	public void genRootCertificate(CA issuer, Integer validity, List <Region> countryList, Integer confidence, Integer assurance,
			Integer minChain, Integer chainRange) throws IOException {
		
		String hostname = issuer.getCaName();
		ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(),DurationTypes.YEARS, validity);		
		
	}

	@Override
	public void genSubCertificate() {
		// TODO Auto-generated method stub
		
	}
	
	/**
	 * Help method that transforms a known string that represents an algorithm into a signature/encryption algorithm needed to create the keys
	 */
	private Signature.SignatureTypes getSignatureType (String alg) {
		
		if(alg.equals("ECIES-Nist") || alg.equals("ECDSA-Nist")) {
			return Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;
		}else {
			return Signature.SignatureTypes.ECDSA_BRAINPOOL_P256R1_SIGNATURE;
		}
			
	}

}
