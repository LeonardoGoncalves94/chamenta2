package com.multicert.v2x.cryptography;

import java.security.KeyPair;
import java.security.KeyStoreException;

public interface DefaultKeystore
{
    /**
     * Method that adds a keypair to the keystore with a certain alias
     */
    void addKeyPair(KeyPair keys, String alias) throws Exception;

    /**
     * Method that retrieves a given key from the keystore
     */
    KeyPair getKeyPair(String alias) throws Exception;

    /**
     * Method that prints the keystore entries (used for testing)
     */
    void printKestore() throws KeyStoreException;
}
