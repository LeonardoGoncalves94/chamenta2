package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Region;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.datastructures.base.CountryOnly;

/**
 * Interface that contains all the methods of the v2x package that will be used by this webapp
 *
 */
public interface V2XService {

	/**
	 * Method that generates a KeyPair and stores it on the keystore
	 */
	void genKey(String alias, String algorithm) throws Exception;
	
	/**
	 * Method that generates a certificate for a Root CA
	 * @throws IOException 
	 */
	void genRootCertificate(CA issuer, Integer validity, List <Region> countryList, Integer confidence, Integer assurance,
			Integer minChain, Integer chainRange) throws IOException;
	
	/**
	 * Method that generates a certificate for a Sub CA
	 */
	void genSubCertificate();

}
