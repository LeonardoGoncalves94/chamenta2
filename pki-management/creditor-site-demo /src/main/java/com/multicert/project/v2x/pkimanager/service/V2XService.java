package com.multicert.project.v2x.pkimanager.service;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.SecretKey;

import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.Certificate;
import com.multicert.project.v2x.pkimanager.model.Key;
import com.multicert.project.v2x.pkimanager.model.Region;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.datastructures.base.CountryOnly;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.EnrollmentResonseCode;
import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

/**
 * Interface that contains all the methods of the v2x package that will be used by this webapp
 *
 */
public interface V2XService {

	/**
	 * Method that generates a KeyPair and stores it on the keystore
	 * @param alias the desired alias
	 * @param algorithm the algorithm of the key pair
	 */
	void genKeyPair(String alias, String algorithm) throws Exception;
	
	/**
	 * Method that gets a given KeyPair from the keystore
	 * @param alias the alias of the desired key pair
	 */
	KeyPair getKeyPair(String alias) throws Exception;
	
	/**
	 * Method that generates a certificate for a Root CA
	 * @return 
	 * @throws IOException 
	 * @throws Exception 
	 */
	byte[] genRootCertificate(Certificate rootCertificate) throws IOException, Exception;
	
	/**
	 * Method that generates a certificate for a Sub CA
	 * @return 
	 * @throws Exception 
	 */
	byte[] genSubCertificate(Certificate subCertificate) throws Exception;

	/**
	 * Method that processes an enrollment request
	 * This method decrypts the request, verifies the vehicle's signature and composes the response
	 * @param encryptedRequest the encoded request
	 * @param decriptionPair the decryption keypair that belong to the destination CA (used to decrypt the request)
	 * @param canonicalKey the canonical public key that belongs to the vehicle (used to verify its signature)
	 * @throws Exception
	 * @returns the enrollment response 
	 */
	EtsiTs103097Data processEcRequest(byte[] encryptedRequest, Certificate destinationCertificate, Key decriptionPair, PublicKey canonicalKey) throws Exception;
	
	/**
	 * Method to extract the PublicKey from the PublicVerificationKey structure
	 * @throws InvalidKeySpecException 
	 */
	PublicKey extractPublicKey(PublicVerificationKey verificationKey) throws InvalidKeySpecException;
	

}
