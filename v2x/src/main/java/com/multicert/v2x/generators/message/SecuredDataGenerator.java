package com.multicert.v2x.generators.message;

import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.asn1.coer.COEROctetString;
import com.multicert.v2x.cryptography.*;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;

import com.multicert.v2x.datastructures.certificate.SequenceOfPsidGroupPermissions;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.InnerEcRequest;
import com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941Data;
import com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941DataContent;
import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo.RecipientInfoChoices;
import com.multicert.v2x.datastructures.message.encrypteddata.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyTypes;
import com.multicert.v2x.datastructures.message.encrypteddata.*;
import com.multicert.v2x.datastructures.message.secureddata.*;
import org.bouncycastle.openssl.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * This class generates secured data such as encrypted and signed data, also it decrypts and verifies signed data
 * An object of SecuredDataGenerator should be instantiated per message decryption/verification
 */
public class SecuredDataGenerator
{
    private static final int CURRENT_VERSION = EtsiTs103097Data.CURRENT_VERSION;
    protected CryptoHelper cryptoHelper;

    private  SecretKey sharedKey;
    private InnerEcRequest innerEcRequest;

    public SecuredDataGenerator(CryptoHelper cryptoHelper)
    {
        this.cryptoHelper = cryptoHelper;
    }


    /**
    * Method to generate an EtsiTs103097Data-Signed structure. //TODO add support for v2x messages, right now only supports certificate requests (signEcRequest)
    * @param hashType
    * @param message the message data to sign.
    * @param headerInfo the header information to include
    * @param signerCertificate the certificate of the signer, null if self-signed
    * @param signerPrivateKey the private key to sign the message
    * @param signingAlgorithm the digital signature algorithm to use
    * @return
    */
    public EtsiTs103097Data createSignedData(HashAlgorithm hashType, byte[] message, HeaderInfo headerInfo, EtsiTs103097Certificate signerCertificate, PrivateKey signerPrivateKey, AlgorithmType signingAlgorithm) throws IOException, NoSuchAlgorithmException, SignatureException
    {
        HashAlgorithm hashedId = hashType;

        EtsiTs103097Data unsecuredData = new EtsiTs103097Data(CURRENT_VERSION, new EtsiTs103097Content(EtsiTs103097Content.EtsiTs103097ContentChoices.UNSECURED_DATA, new Opaque(message)));
        ToBeSignedData toBeSignedData = new ToBeSignedData(new SignedDataPayload(unsecuredData, null), headerInfo);

        SignerIdentifier signer;
        if(signerCertificate == null)
        {
             signer = new SignerIdentifier(); // set to SELF
        }
        else
        {
             signer = new SignerIdentifier(cryptoHelper.getCertificateHashId(signerCertificate, hashType)); // set to DIGEST
        }

        Signature signature = cryptoHelper.signEcRequest(toBeSignedData.getEncoded(), signerPrivateKey, signingAlgorithm);

        SignedData signedData = new SignedData(hashedId, toBeSignedData, signer, signature);

        EtsiTs103097Content etsiTs103097Content = new EtsiTs103097Content(signedData);
        return new EtsiTs103097Data(etsiTs103097Content);
    }

    /**
     * Method used to verify an ECRequest, when the vehicle does not have a certificate (see com.multicert.v2x.generators.certificaterequest fro more information)
     * This method verifies both signed data structures of the enrollment request.
     * The outer signature is verified with the vehicle's canonical public key. (identify the vehicle)
     * The inner signature is verified with the public key that exists on the InnerEcRequest structure. (proof of possession of the verification key)
     * @param signedData the decrypted Enrollment Credential Request (OuterEcRequest)
     * @param canonicalPubKey the vehicle's canonical public key to verify the OuterEcRequest
     * @return
     * @throws IllegalArgumentException
     * @throws SignatureException
     * @throws IOException
     */
    public void verifySignedRequest(EtsiTs103097Data signedData, PublicKey canonicalPubKey) throws IllegalArgumentException, SignatureException, ImcompleteRequestException, BadContentTypeException, IOException, InvalidSignatureException, InvalidKeySpecException
    {
        if(signedData.getContent().getType() != EtsiTs103097Content.EtsiTs103097ContentChoices.SIGNED_DATA)
        {
            throw new BadContentTypeException("Error verifying outer signature: Only signed EtsiTs103097Data can verified");
        }
        SignedData sd = (SignedData) signedData.getContent().getValue();
        EtsiTs103097Data payloadData = sd.getTbsData().getPayload().getData();
        if(payloadData == null){
            throw new ImcompleteRequestException("Error verifying outer signature, no payload data found");
        }

        Boolean outerSignatureResult = false;
        //try to verify the outer signature using the shared vehicle canonical public key
        try
        {
            outerSignatureResult = cryptoHelper.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), canonicalPubKey);

        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("problem while verifying outer signature");
        }

         //Get to the inner signed structure
        EtsiTs102941Data etsiTs102941Data =  new EtsiTs102941Data(((Opaque) payloadData.getContent().getValue()).getData());
        if(etsiTs102941Data.getContent().getType() != EtsiTs102941DataContent.EtsiTs102941DataContentTypes.ENROLLMENT_REQUEST)
        {
            throw new BadContentTypeException("Error verifying EcRequest: specified structure is not and enrollment credential request");
        }
        EtsiTs103097Data InnerECRequestSignedForPOP = (EtsiTs103097Data)etsiTs102941Data.getContent().getValue();

        Boolean innerSignatureResult = false;
        //try Verify the inner signed  structure
        try
        {
            innerSignatureResult = verifyInnerSignature(InnerECRequestSignedForPOP);
        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("problem while verifying inner signature");
        }

        //If a signature is invalid the whole request is invalid
        if(!(outerSignatureResult & innerSignatureResult))
        {
            throw new InvalidSignatureException("The signature does not verify");
        }
    }

    /**
     * Methot hat verifies the inner signature of the enrollment request See package com.multicert.v2x.generators.certificaterequest;

     * @return
     */
    private Boolean verifyInnerSignature(EtsiTs103097Data InnerECRequestSignedForPOP) throws SignatureException, BadContentTypeException, ImcompleteRequestException, IOException, InvalidKeySpecException
    {
        if(InnerECRequestSignedForPOP.getContent().getType() != EtsiTs103097Content.EtsiTs103097ContentChoices.SIGNED_DATA){
            throw new BadContentTypeException("Error verifying inner signature: Only signed EtsiTs103097Data can verified");
        }

            SignedData sd = (SignedData) InnerECRequestSignedForPOP.getContent().getValue();
            EtsiTs103097Data payloadData = sd.getTbsData().getPayload().getData();
            if (payloadData == null)
            {
                throw new ImcompleteRequestException("Error verifying inner signature, no payload data found");
            }

            innerEcRequest = new InnerEcRequest(((Opaque) payloadData.getContent().getValue()).getData());

            PublicKey verificationKey = getRequestPublicKey();

            return cryptoHelper.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), verificationKey);


    }

    /**
     * Method that returns the innerECRequest structure
     * @throws IOException
     */
    public InnerEcRequest getInnerEcRequest() throws IOException
    {
        return innerEcRequest;
    }

    /**
     * Help method to read the ITS public key from the decrypted and verified  request
     * @return
     */
    public PublicKey getRequestPublicKey() throws InvalidKeySpecException
    {
        AlgorithmType sigAlgorithm = innerEcRequest.getPublicKeys().getVerificationKey().getType();
        EccP256CurvePoint point = (EccP256CurvePoint) innerEcRequest.getPublicKeys().getVerificationKey().getValue();

        PublicKey verificationKey = (PublicKey) cryptoHelper.eccPointToPublicKey(sigAlgorithm,point);
        return verificationKey;
    }


    /**
     * Help method to read requested cert issue permissions the decrypted and verified request
     * @return
     */
    public SequenceOfPsidGroupPermissions getCertIssuePermissions()
    {

        return innerEcRequest.getRequestedSubjectAttributes().getCertIssuePermissions();
    }




    /**
     * Method that encrypts data to a list of recipients
     *
     */
    public EtsiTs103097Data createEncryptedData(SequenceOfRecipientInfo sequenceOfRecipientInfo, byte[] tobeEncryptedData, AlgorithmType alg, SecretKey symmKey) throws IOException, GeneralSecurityException
    {
        byte[] nounce = cryptoHelper.generateNounce(alg);
        byte[] cipherText = cryptoHelper.encryptSymmetric(alg, symmKey, nounce, tobeEncryptedData);

        AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nounce,cipherText);
        SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(aesCcmCiphertext);
        EncryptedData encryptedData = new EncryptedData(sequenceOfRecipientInfo,symmetricCiphertext);

        EtsiTs103097Content etsiTs103097Content = new EtsiTs103097Content(encryptedData);
        return new EtsiTs103097Data(etsiTs103097Content);
    }


    /**
     * Method that decrypts data a to certificate receiver (CERT_RECIP_INFO)
     * @param  encryptedData the data to decrypt
     * @param receiverCert the certificate of the receiver
     * @param privateKey the private key associated with the receiver certificate
     *
     */
    public byte[] decryptEncryptedData(EtsiTs103097Data encryptedData, EtsiTs103097Certificate receiverCert, PrivateKey privateKey) throws IOException, GeneralSecurityException, IncorrectRecipientException, BadContentTypeException, DecryptionException
    {


        if(encryptedData.getContent().getType() != EtsiTs103097Content.EtsiTs103097ContentChoices.ENCRYPTED_DATA){

            throw new BadContentTypeException("Error decrypting EncryptedData: invalid data type " + encryptedData.getContent().getType() +" only the type ENCRYPTED_DATA can be decrypted.");
        }

        EncryptedData data = (EncryptedData) encryptedData.getContent().getValue();
        COEREncodable[] recipientInfos = data.getRecipients().getValues();

        SecretKey decryptionKey = null;
        HashedId8 receiverId = cryptoHelper.getCertificateHashId(receiverCert,HashAlgorithm.SHA_256); //generate the Id for the receiver certificate

        for(COEREncodable ri : recipientInfos)
        {
            RecipientInfo recipientInfo = (RecipientInfo) ri;

            HashedId8 reference = getRecipientId(recipientInfo); // get the recipient Id present in the encrypted data

            if(receiverId.toString().equals(reference.toString())) //if they match, the encrypted data was sent to this specific receiverCert
            {
                try
                {
                    PKRecipientInfo pkRecInfo = (PKRecipientInfo) recipientInfo.getValue();
                    decryptionKey = cryptoHelper.eceisDecryptSymmetricKey(pkRecInfo.getEncKey(), privateKey, pkRecInfo.getEncKey().getType());
                    sharedKey = decryptionKey;

                    SymmetricCiphertext symmetricCiphertext = data.getCipherText();

                    return cryptoHelper.symmetricDecrypt(symmetricCiphertext.getType(), getEncryptedData(symmetricCiphertext), decryptionKey, getNounce(symmetricCiphertext));
                }catch(Exception e)
                {
                    throw new DecryptionException("Error decrypting data");
                }

            }
        }

        throw new IncorrectRecipientException("Error decrypting data, no matching receiver info could be found to retrieve the decryption key.");

    }

    public SecretKey getSharedKey()
    {
        return sharedKey;
    }


    //TODO TEST THIS
    /**
     * Help method that creates the enrollment request hash to be included in  the enrollment response
     * @param request the request from which to create digest
     */
    public COEROctetString createRequestHash(EtsiTs103097Data request) throws IOException, NoSuchAlgorithmException
    {
        byte[] fullDigest = cryptoHelper.digest(request.getEncoded(),HashAlgorithm.SHA_256);
        byte[] result = new byte[16];
        System.arraycopy(fullDigest, 0, result, 0, 16);
        return new COEROctetString(result,16,16);
    }

    /**
     * This method generated the HashedId8 certificate identifier value
     */
    public SecretKey createSecretKey(AlgorithmType alg) throws IOException, NoSuchAlgorithmException
    {
        return cryptoHelper.genSecretKey(alg);
    }

    /**
     * This method generates a recipient info of type CERT_RECIP_INFO (encrypt to a certificate holder)
     *
     */
    public RecipientInfo genRecipientInfo(EtsiTs103097Certificate recipientCert, SecretKey symmKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
    {
        if(recipientCert.getTbsCert().getEncryptionKey() == null){
            throw new IllegalArgumentException("Error encrypting EC request: The EA certificate cannot be used as encryption receipient, no public encryption key found.");
        }

        HashedId8 recipientId = cryptoHelper.getCertificateHashId(recipientCert, HashAlgorithm.SHA_256);
        PublicEncryptionKey publicEncryptionKey = recipientCert.getTbsCert().getEncryptionKey();
        AlgorithmType publicKeyAlg = publicEncryptionKey.getPublicKey().getType();
        PublicKey certificateEncKey = (PublicKey) cryptoHelper.eccPointToPublicKey(publicKeyAlg, (EccP256CurvePoint) publicEncryptionKey.getPublicKey().getValue());

        EncryptedDataEncryptionKey encryptedKey = cryptoHelper.eceisEncryptSymmetricKey(getEnckeyType(publicKeyAlg), publicEncryptionKey.getSupportedSymmalgorith(),certificateEncKey,symmKey);

        PKRecipientInfo pkRecipientInfo = new PKRecipientInfo(recipientId, encryptedKey);

        return new RecipientInfo(RecipientInfoChoices.CERT_RECIP_INFO, pkRecipientInfo);
    }

    /**
     * This method generates a recipient info of type PSK_RECIP_INFO (encrypt to a pre-shared-key recipient)
     *
     */
    public RecipientInfo genRecipientInfo(SecretKey preSharedKey)
    {
       return new RecipientInfo(new PreSharedKeyRecipientInfo(preSharedKey.getEncoded()));
    }

    /**
     * Help method that returns a reference to a recipient from the recipient information
     */
    protected HashedId8 getRecipientId(RecipientInfo recipientInfo) {
        switch (recipientInfo.getType()) {
            case PSK_RECIP_INFO:
                return (PreSharedKeyRecipientInfo) recipientInfo.getValue();
            case SYMM_RECIP_INFO:
                SymmRecipientInfo sri = (SymmRecipientInfo) recipientInfo.getValue();
                return sri.getRecipientId();
            case CERT_RECIP_INFO:
            case SIGNED_DATA_RECIP_INFO:
            case REK_RECIP_INFO:
                PKRecipientInfo pri = (PKRecipientInfo) recipientInfo.getValue();
                return pri.getRecipientId();
            default:
        }
        throw new IllegalArgumentException("Unknown RecipientInfo type: " + recipientInfo.getType());
    }

    //TODO other forms of RecipientInfo

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

    public static byte[] getEncryptedData(SymmetricCiphertext symmetricCiphertext) {
        switch (symmetricCiphertext.getType()) {
            default:
            case AES_128_CCM:
                AesCcmCiphertext aesCcmCiphertext = (AesCcmCiphertext) symmetricCiphertext.getValue();
                return aesCcmCiphertext.getCcmCipherText();
        }
    }

    public static byte[] getNounce(SymmetricCiphertext symmetricCiphertext) {
        switch (symmetricCiphertext.getType()) {
            default:
            case AES_128_CCM:
                AesCcmCiphertext aesCcmCiphertext = (AesCcmCiphertext) symmetricCiphertext.getValue();
                return aesCcmCiphertext.getNounce();
        }
    }

}
