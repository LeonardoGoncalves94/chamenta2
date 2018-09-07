package com.multicert.project.v2x.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;

/**
 * Interface with the v2x package
 *
 */
public interface V2X {
	/**
	 * Method that generates an elliptic curve key pair
	 * @param alg the algorithm of the key, the possible types are present in the Signature.SignatureTypes Enum
	 * @return
	 * @throws Exception
	 */
	KeyPair genKeyPair(AlgorithmType alg) throws Exception;
	
	/**
	 * Method that wraps an elliptic curve generated key into a PublicVerificationKey structure (contains the curve point and algorithm)
	 * @param publicKey the public key to wrap
	 * @param alg the algorithm of the key to wrap
	 * @return
	 * @throws IllegalArgumentException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public PublicVerificationKey buildVerificationKey(PublicKey publicKey, AlgorithmType alg) throws IllegalArgumentException, InvalidKeySpecException, IOException;
}
