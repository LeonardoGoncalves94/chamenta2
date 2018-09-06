package com.multicert.project.v2x.client;

import java.security.KeyPair;

import com.multicert.v2x.cryptography.AlgorithmType;

/**
 * Interface with the v2x package
 *
 */
public interface V2X {

	KeyPair genKeyPair(AlgorithmType alg) throws Exception;
}
