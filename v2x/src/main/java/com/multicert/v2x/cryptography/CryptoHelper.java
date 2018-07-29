package com.multicert.v2x.cryptography;

import com.multicert.v2x.asn1.coer.COEROctetString;
import com.multicert.v2x.asn1.coer.EncodeHelper;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.base.EccP256CurvePoint.*;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.certificate.CertificateBase;
import com.multicert.v2x.datastructures.message.encrypteddata.EncryptedDataEncryptionKey;
import com.multicert.v2x.datastructures.message.encrypteddata.EncryptedDataEncryptionKey.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;


/**
 *Implementation of the CryptoHelper with support to ecdsa_nistp256_with_sha256 and ecies_nistp256 algorithms
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 */
public class CryptoHelper {


    protected KeyPairGenerator ecNistP256Generator;
    protected KeyPairGenerator brainpoolp256r1P256Generator;
    protected KeyGenerator aesGenerator;
    protected ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256");
    protected ECParameterSpec brainpoolp256r1P256Spec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
    protected SecureRandom secureRandom = new SecureRandom();
    protected static final int AES_PARAM = 128;
    protected KeyFactory keyFactory;
    protected MessageDigest sha256Digest;
    protected JcePKCS12 jcePKCS12;
    protected IESCipher iesCipher = new IESCipher(new IESEngine(new ECDHCBasicAgreement(),
            new KDF2BytesGenerator(new SHA256Digest()),
            new Mac(new SHA256Digest(),128)));


    protected String provider;


    /**
     * Constructor used when instantiating a cryptohelper with a different provider
     * @param provider
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public CryptoHelper(String provider) throws Exception
    {
        this.provider = provider;
        try
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }
            ecNistP256Generator = KeyPairGenerator.getInstance("ECDSA", provider);
            ecNistP256Generator.initialize(ecNistP256Spec, secureRandom);
            brainpoolp256r1P256Generator = KeyPairGenerator.getInstance("ECDSA", provider);
            brainpoolp256r1P256Generator.initialize(brainpoolp256r1P256Spec, secureRandom);
            aesGenerator = KeyGenerator.getInstance("AES", provider);
            aesGenerator.init(AES_PARAM);
            jcePKCS12 = new JcePKCS12();

            //TODO ecqvHelper = new ECQVHelper(this);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new NoSuchAlgorithmException("Error initializing CryptoHeler: Invalid algorithm parameter" + e.getMessage(),e);
        }

    }

    /**
     * Method that generates a keypair given a digital signing algorithm
     *
     * Use ECDSA_NIST_P256_SIGNATURE for Nist generator and ECDSA_BRAINPOOL_P256R1_SIGNATURE for Brainpool generator
     */
    public KeyPair genKeyPair(AlgorithmType algorithm, String alias) throws Exception
    {

        if(algorithm == null)
        {
            throw new IllegalArgumentException("Error generating key pair: Algorithm must not be null");
        }
        if(algorithm.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_NIST_P256)
        {
            KeyPair keys = ecNistP256Generator.generateKeyPair();
            jcePKCS12.addKeyPair(keys, alias);
            return keys;

        }
        if(algorithm.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_BRAINPOOL_P256R1)
        {
            KeyPair keys = brainpoolp256r1P256Generator.generateKeyPair();
            jcePKCS12.addKeyPair(keys, alias);
            return keys;
        }
        throw new IllegalArgumentException("Error generating key pair: Unsupported algorithm" + algorithm);
    }

    /**
     * Method that generates a keypair given a digital signing algorithm
     *
     * Use ECDSA_NIST_P256_SIGNATURE for Nist generator and ECDSA_BRAINPOOL_P256R1_SIGNATURE for Brainpool generator
     */
    public KeyPair getKeyPair( String alias) throws Exception
    {
        return jcePKCS12.getKeyPair(alias);

    }

    public void printKeyStore() throws Exception
    {
        jcePKCS12.printKestore();
    }

    public SecretKey genSecretKey(AlgorithmType alg)
    {
        if(alg.getAlgorithm().getSymmetric() != Algorithm.Symmetric.AES_128_CCM)
        {
            throw new IllegalArgumentException("Error generating secret key: unsupported algorithm:" +alg);
        }
        return aesGenerator.generateKey();
    }

    public SecretKey constructSecretKey(AlgorithmType alg, byte[] keyData)
    {
        if(alg.getAlgorithm().getSymmetric() != Algorithm.Symmetric.AES_128_CCM){
            throw new IllegalArgumentException("Error constructing secret key: unsupported algorithm: " + alg);
        }
        return new SecretKeySpec(keyData, "AES");
    }

    /**
     * Method that converts a public key of a given algorithm to a EccP256CurvePoint structure
     *
     */
    public EccP256CurvePoint getECPoint(AlgorithmType alg, EccP256CurvePointTypes type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException, IOException
    {
        if(! (publicKey instanceof java.security.interfaces.ECPublicKey))
        {
            throw new IllegalArgumentException("Error converting public key to ECC curve point: Only EC public keys are supported");
        }
        BCECPublicKey bcPub = toBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);

        if(type == EccP256CurvePointTypes.UNCOMPRESSED){
            return new EccP256CurvePoint(bcPub.getW().getAffineX(), bcPub.getW().getAffineY());
        }
        if(type == EccP256CurvePointTypes.COMPRESSED_Y_0 || type == EccP256CurvePointTypes.COMPRESSED_Y_1){
            return new EccP256CurvePoint(bcPub.getQ().getEncoded(true));
        }
        if(type == EccP256CurvePointTypes.X_ONLY){
            return new EccP256CurvePoint(bcPub.getW().getAffineX());
        }

        throw new IllegalArgumentException("Unsupported ecc point type: " + type);
    }

    /**
     * Help method that converts ECC point into public key
     */
    public Object getPublicKey(AlgorithmType alg, EccP256CurvePoint eccPoint) throws InvalidKeySpecException {
        switch(eccPoint.getType()){
            case FILL:
                throw new InvalidKeySpecException("Unsupported EccPoint type: fill");
            case X_ONLY:
                byte[] data = ((COEROctetString) eccPoint.getValue()).getData();
                return new BigInteger(1,data);
            case COMPRESSED_Y_0:
            case COMPRESSED_Y_1:
                byte[] compData = ((COEROctetString) eccPoint.getValue()).getData();
                byte[] compressedEncoding = new byte[compData.length +1];
                System.arraycopy(compData, 0, compressedEncoding, 1, compData.length);
                if(eccPoint.getType() == EccP256CurvePointTypes.COMPRESSED_Y_0){
                    compressedEncoding[0] = 0x02;
                }else{
                    compressedEncoding[0] = 0x03;
                }
                return getECPublicKeyFromECPoint(alg, getECCurve(alg).decodePoint(compressedEncoding));
            case UNCOMPRESSED:
                UncompressedEccPoint uep = (UncompressedEccPoint) eccPoint.getValue();
                BigInteger x = new BigInteger(1, uep.getX());
                BigInteger y = new BigInteger(1, uep.getY());
                return getECPublicKeyFromECPoint(alg, getECCurve(alg).createPoint(x, y));
        }
        return null;
    }

    protected ECPublicKey getECPublicKeyFromECPoint(AlgorithmType alg, ECPoint eCPoint) throws InvalidKeySpecException{
        ECPublicKeySpec spec = new ECPublicKeySpec(eCPoint, getECParameterSpec(alg));
        return (ECPublicKey) keyFactory.generatePublic(spec);
    }

    protected BCECPublicKey toBCECPublicKey(AlgorithmType alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException
    {
        if(ecPublicKey instanceof BCECPublicKey)
        {
            return (BCECPublicKey) ecPublicKey;
        }

        org.bouncycastle.math.ec.ECPoint ecPoint = EC5Util.convertPoint(getECCurve(alg), ecPublicKey.getW(), false);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, getECParameterSpec(alg));

        return (BCECPublicKey) keyFactory.generatePublic(keySpec);
    }

    public Signature signCertificateRequest(byte[] tbsData, PrivateKey signerPrivateKey, AlgorithmType signingAlgorithm) throws NoSuchAlgorithmException, IOException, SignatureException
    {
        if(signingAlgorithm == null){
            throw new IllegalArgumentException("Error signing certificate request: no signature algorithm specified");
        }

        byte[] messageDigest = digest(tbsData, signingAlgorithm);
        signMessageDigest(messageDigest, signingAlgorithm, signerPrivateKey);
        return null;
    }


    public Signature signMessage(byte[] tbsData, AlgorithmType signingAlgorithm, CertificateBase issuerCertificate, PrivateKey signingKey) throws SignatureException
    {
        if(signingAlgorithm.getAlgorithm().getSignature() == null)
        {
            throw new IllegalArgumentException("Error signing certificate: No signature algorithm indicated");
        }

        try
        {
            return signMessageDigest(digestCertificate(tbsData, signingAlgorithm, issuerCertificate), signingAlgorithm, signingKey);
        } catch (SignatureException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }

        throw new SignatureException("Error creating signature");
    }

    /**
     * This method creates a certificate digest to be used in the certificate's signature according to the ieee1609.2 standards
     * @param tbsData the to be signed certificate data
     * @param hashAlgorithm the algorithm to ude
     * @param issuerCertificate the certificate used for signing
     */
    public byte[] digestCertificate(byte[] tbsData, AlgorithmType hashAlgorithm, CertificateBase issuerCertificate) throws NoSuchAlgorithmException, IOException
    {
        byte[] dataDigest = digest(tbsData, hashAlgorithm);
        byte[] signerDigest;

        if(issuerCertificate == null)
        {
            signerDigest = digest(new byte[0], hashAlgorithm);
        }
        else
        {
            signerDigest = digest(issuerCertificate.getEncoded(), hashAlgorithm);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(dataDigest);
        baos.write(signerDigest);

        byte[] result = digest(baos.toByteArray(), hashAlgorithm);
        return result;
    }

    public byte[] digest(byte[] message, AlgorithmType hashAlgorithm) throws IllegalArgumentException, NoSuchAlgorithmException {

        if(hashAlgorithm != null && hashAlgorithm.getAlgorithm().getHash() == Algorithm.Hash.SHA_256){
            sha256Digest.reset();
            sha256Digest.update(message);
            return sha256Digest.digest();
        }else{
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
    }

    public Signature signMessageDigest(byte[] digest, AlgorithmType signingAlgorithm, PrivateKey privateKey) throws SignatureException, IOException
    {
        if (signingAlgorithm == null)
        {
            throw new IllegalArgumentException("Error signing digest: no signature algorithm specified");
        }

        ASN1InputStream asn1InputStream = null;
        try
        {
            java.security.Signature signature = java.security.Signature.getInstance("NONEwithECDSA", provider);
            signature.initSign(privateKey);
            signature.update(digest);
            byte[] dERSignature = signature.sign();

            ByteArrayInputStream inStream = new ByteArrayInputStream(dERSignature);
            asn1InputStream = new ASN1InputStream(inStream);

            DLSequence dLSequence = (DLSequence) asn1InputStream.readObject();
            BigInteger r = ((ASN1Integer) dLSequence.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) dLSequence.getObjectAt(1)).getPositiveValue();

            int signatureSize = Algorithm.Signature.size;
            ByteArrayOutputStream baos = new ByteArrayOutputStream(signatureSize);
            EncodeHelper.writeFixedFieldSizeKey(signatureSize, baos, s);
            return new Signature(getSignatureType(signingAlgorithm), new EcdsaP256Signature(new EccP256CurvePoint(r),baos.toByteArray()));
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        catch (SignatureException e)
        {
            e.printStackTrace();
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchProviderException e)
        {
            e.printStackTrace();
        }
        finally
        {
            if(asn1InputStream != null)
            {
                asn1InputStream.close();
            }
        }

        throw new SignatureException("Error creating signature");
    }

    protected ECCurve getECCurve (AlgorithmType alg)
    {
        if (alg.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_NIST_P256)
        {
            return new SecP256R1Curve(); //Nist curve

        }
        if ((alg.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_BRAINPOOL_P256R1))
        {
            return TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1).getCurve(); //Brainpool curve
        }
        throw new IllegalArgumentException("Unsupported EC Algorithm: " + alg);
    }

    protected Signature.SignatureTypes getSignatureType(AlgorithmType signingAlgorithm)
    {
        if(signingAlgorithm.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_NIST_P256)
        {
            return Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;
        }
        if(signingAlgorithm.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_BRAINPOOL_P256R1)
        {
            return Signature.SignatureTypes.ECDSA_BRAINPOOL_P256R1_SIGNATURE;
        }
        throw new IllegalArgumentException("Unsupported Signature algorithm: "+signingAlgorithm);
    }

    protected ECParameterSpec getECParameterSpec(AlgorithmType alg)
    {
        if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_NIST_P256)
        {
            return ecNistP256Spec;
        }
        if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ECDSA_BRAINPOOL_P256R1)
        {
            return brainpoolp256r1P256Spec;
        }
        throw new IllegalArgumentException("Unsupported EC Algorithm: " +alg);
    }

    public HashAlgorithm getHashAlgorithm(AlgorithmType alg)
    {
        if(alg.getAlgorithm().getHash() != Algorithm.Hash.SHA_256)
        {
            throw new IllegalArgumentException("Error getting hash algorithm: Unsupported algorithm"+ alg);
        }
        return HashAlgorithm.SHA_256;
    }

    public byte[] encryptSymmetric(AlgorithmType alg, Key symmetricKey, byte[] nounce, byte[] data) throws IllegalArgumentException, GeneralSecurityException
    {
        Cipher cipher = getSymmetricCihper(alg);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(nounce));
        return cipher.doFinal(data);
    }

    public byte[] generateNounce(AlgorithmType alg) throws IllegalArgumentException, GeneralSecurityException{
        if( alg.getAlgorithm().getSymmetric() == null){
            throw new IllegalArgumentException("Error generating nounce: algorithm scheme does not support symmetric encryption");
        }
        int nounceLen = alg.getAlgorithm().getSymmetric().getNounceLength();
        byte[] nounce = new byte[nounceLen];
        secureRandom.nextBytes(nounce);

        return nounce;
    }


    protected Cipher getSymmetricCihper(AlgorithmType alg) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
    {
        if(alg.getAlgorithm().getSymmetric() != Algorithm.Symmetric.AES_128_CCM)
        {
            throw new IllegalArgumentException("Error encrypting/decrypting data: invalid algorithm" + alg);
        }
        return Cipher.getInstance("AES/CCM/NoPadding", "BC");
    }

    protected byte[] decryptSymmetric(AlgorithmType alg, Key symmetricKey, byte[] nounce, byte[] data) throws IllegalArgumentException, GeneralSecurityException
    {
        Cipher cipher = getSymmetricCihper(alg);
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(nounce));
        return cipher.doFinal(data);
    }

    public EncryptedDataEncryptionKey eceisEncryptSymmetricKey(EncryptedDataEncryptionKeyTypes keyType, AlgorithmType alg, PublicKey encryptionKey, SecretKey symmKey) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] keyData = symmKey.getEncoded();

        iesCipher.engineInit(Cipher.ENCRYPT_MODE, encryptionKey, new IESParameterSpec(null, null, 128,-1, null, true),secureRandom);

        byte[] encryptedData = iesCipher.engineDoFinal(keyData, 0, keyData.length);
        byte[] v = new byte[keyType.getVLength()];
        System.arraycopy(encryptedData, 0, v, 0,keyType.getVLength());

        EccP256CurvePoint p = new EccP256CurvePoint(v);

        byte[] c = new byte[alg.getAlgorithm().getSymmetric().getKeyLength()];
        byte[] t = new byte[keyType.getOutputTagLength()];
        System.arraycopy(encryptedData, keyType.getVLength(), c, 0, alg.getAlgorithm().getSymmetric().getKeyLength());
        System.arraycopy(encryptedData, keyType.getVLength() + alg.getAlgorithm().getSymmetric().getKeyLength(), t, 0, keyType.getOutputTagLength());

        EciesP256EncryptedKey key = new EciesP256EncryptedKey(p,c,t);
        return new EncryptedDataEncryptionKey(keyType, key);
    }


    /**
     * This method generated the HashedId8 certificate identifier value
     */
    public HashedId8 getCertificateHashId(CertificateBase certificate, AlgorithmType hashAlgorithm) throws IOException, NoSuchAlgorithmException
    {
        return new HashedId8(digest(certificate.getEncoded(), hashAlgorithm));
    }

}
