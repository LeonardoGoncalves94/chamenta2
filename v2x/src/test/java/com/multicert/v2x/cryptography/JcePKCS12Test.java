package com.multicert.v2x.cryptography;

import  com.multicert.v2x.cryptography.JcePKCS12;
import com.multicert.v2x.datastructures.base.Signature;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class JcePKCS12Test
{
    @Test
    public void testsotreAndGetKeyPair() throws Exception
    {
        // generate the cryptohelper to internally initialize the keystore
        CryptoHelper cryptoHelper = new CryptoHelper("BC");

        // generate a keypair and store it on the keystore
        KeyPair keyPair = cryptoHelper.genKeyPair(Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE, "keys1");
        KeyPair keyPair2 = cryptoHelper.genKeyPair(Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE, "keys2");

        cryptoHelper.printKeyStore();

        //get the keypair from the cryptohelper internal keystore
        KeyPair returnedKeyPair = cryptoHelper.getKeyPair("keys1");

        assertEquals(keyPair.getPrivate(), returnedKeyPair.getPrivate());
        assertEquals(keyPair.getPublic(), returnedKeyPair.getPublic());


    }

}