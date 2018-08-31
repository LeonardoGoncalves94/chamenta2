package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.security.KeyPair;
import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Certificate;
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
	void genKeyPair(String alias, String algorithm) throws Exception;

	
	/**
	 * Method that generates a certificate for a Root CA
	 * @return 
	 * @throws IOException 
	 * @throws Exception 
	 */
	public byte[] genRootCertificate(Certificate rootCertificate) throws IOException, Exception;
	
	/**
	 * Method that generates a certificate for a Sub CA
	 * @return 
	 * @throws Exception 
	 */
	byte[] genSubCertificate(Certificate subCertificate) throws Exception;

}
