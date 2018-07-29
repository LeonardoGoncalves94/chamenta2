package com.multicert.v2x.generators.message;

import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.certificate.CertificateBase;

import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo.RecipientInfoChoices;
import com.multicert.v2x.datastructures.message.encrypteddata.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyTypes;
import com.multicert.v2x.datastructures.message.encrypteddata.*;
import com.multicert.v2x.datastructures.message.secureddata.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class SecuredDataGenerator
{
    private static final int CURRENT_VERSION = Ieee1609Dot2Data.CURRENT_VERSION;
    protected CryptoHelper cryptoHelper;

    public SecuredDataGenerator(CryptoHelper cryptoHelper)
    {
        this.cryptoHelper = cryptoHelper;
    }


/**
 * Method to generate an EtsiTs103097Data-Signed structure. //TODO add support for v2x messages, right now only supports certificate requests (signCertificateRequest)
 * @param hashType
 * @param message the message data to sign.
 * @param headerInfo the header information to include
 * @param signerIdentifier the type of signer to include
 * @param signerPrivateKey the private key to sign the message
 * @param signingAlgorithm the digital signature algorithm to use
 * @return
 */
    public Ieee1609Dot2Data createSignedData(HashAlgorithm hashType, byte[] message, HeaderInfo headerInfo, SignerIdentifier signerIdentifier, PrivateKey signerPrivateKey, AlgorithmType signingAlgorithm) throws IOException, NoSuchAlgorithmException, SignatureException
    {
        HashAlgorithm hashedId = hashType;
        Ieee1609Dot2Data unsecuredData = new Ieee1609Dot2Data(CURRENT_VERSION, new Ieee1609Dot2Content(Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.UNSECURED_DATA, new Opaque(message)));
        ToBeSignedData toBeSignedData = new ToBeSignedData(new SignedDataPayload(unsecuredData, null), headerInfo);
        SignerIdentifier signer = signerIdentifier;
        Signature signature = cryptoHelper.signCertificateRequest(toBeSignedData.getEncoded(), signerPrivateKey, signingAlgorithm);

        SignedData signedData = new SignedData(hashType, toBeSignedData, signer, signature);

        Ieee1609Dot2Content ieee1609Dot2Content = new Ieee1609Dot2Content(signedData);
        return new Ieee1609Dot2Data(ieee1609Dot2Content);
    }

    /**
     * Method that encrypts data to a list of recipients
     *
     */
    public Ieee1609Dot2Data createEncryptedData(SequenceOfRecipientInfo sequenceOfRecipientInfo, byte[] tobeEncryptedData, AlgorithmType alg, SecretKey symmKey ) throws IOException, GeneralSecurityException
    {
        byte[] nounce = cryptoHelper.generateNounce(alg);
        byte[] cipherText = cryptoHelper.encryptSymmetric(alg, symmKey, nounce, tobeEncryptedData);

        AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nounce,cipherText);
        SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(aesCcmCiphertext);
        EncryptedData encryptedData = new EncryptedData(sequenceOfRecipientInfo,symmetricCiphertext);

        Ieee1609Dot2Content ieee1609Dot2Content = new Ieee1609Dot2Content(encryptedData);
        return new Ieee1609Dot2Data(ieee1609Dot2Content);
    }



    /**
     * This method generated the HashedId8 certificate identifier value
     */
    public SecretKey getSecretKey( AlgorithmType alg) throws IOException, NoSuchAlgorithmException
    {
        return cryptoHelper.genSecretKey(alg);
    }

    /**
     * This method generates a recipient info of type certRecipInfo (encrypt to a certificate holder)
     *
     */
    public RecipientInfo getRecipientInfo(CertificateBase recipientCert, SecretKey symmKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
    {

        HashedId8 recipientId = cryptoHelper.getCertificateHashId(recipientCert, HashAlgorithm.SHA_256);
        PublicEncryptionKey publicEncryptionKey = recipientCert.getTbsCert().getEncryptionKey();
        AlgorithmType publicKeyAlg = publicEncryptionKey.getPublicKey().getType();
        PublicKey certificateEncKey = (PublicKey) cryptoHelper.getPublicKey(publicKeyAlg, (EccP256CurvePoint) publicEncryptionKey.getPublicKey().getValue());

        EncryptedDataEncryptionKey encryptedKey = cryptoHelper.eceisEncryptSymmetricKey(getEnckeyType(publicKeyAlg), publicEncryptionKey.getSupportedSymmalgorith(),certificateEncKey,symmKey);

        PKRecipientInfo pkRecipientInfo = new PKRecipientInfo(recipientId, encryptedKey);

        return new RecipientInfo(RecipientInfoChoices.CERT_RECIP_INFO, pkRecipientInfo);
    }

    public EncryptedDataEncryptionKeyTypes getEnckeyType (AlgorithmType alg)
    {
        if(alg.getAlgorithm().getSignature() == null){
            throw new IllegalArgumentException("Error unsupported algorithm: " + alg);
        }

        switch(alg.getAlgorithm().getEncryption()){
            case ECIES_Nist_P256:
                return EncryptedDataEncryptionKeyTypes.ECIES_NIST_P256;
            case ECIES_BRAINPOOL_P256R1:
            default:
                return EncryptedDataEncryptionKeyTypes.ECIES_BRAINPOOL_P256R1;
        }
    }


    //TODO other forms of RecipientInfo
}
