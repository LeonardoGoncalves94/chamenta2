package com.multicert.v2x.generators.certificate;



import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.certificate.*;
import com.multicert.v2x.datastructures.base.BasePublicEncryptionKey.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

/**
 * Class for generating certificates for the root CA, enrollment CA and authorization authority.
 * Such certificates contain the subject's permissions to sign other certificates and to sign certificate response messages contained in a EtsiTs103097Data. (cert request permissions is ABSENT)
 * The app permissions are static (set by the certificate profile) therefore they are set on each certificate generation method
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 *
 */
public class CACertGenerator extends CertificateGenerator
{

    public CACertGenerator(CryptoHelper cryptoHelper, boolean isCompressed)
    {
        super(cryptoHelper, isCompressed);
    }

    /**
     * This method generates a root CA certificate according to the profile defined in the ETSI TS 103 097 standard
     * @param hostname a unique Root CA name, Required (according to the standard 103 097, the certificateId shall always be hostname for the rootCA)
     * @param validityPeriod the validity period for this certificate, Required
     * @param geographicRegionegion the validity region for this certificate, Required
     * @param assuranceLevel the assurance level for this certificate (0-7), Required
     * @param confidenceLevel the confidence level for this certificate (0-3), Required
     * @param minChainDepth the minimal chain length of this PKI hierarchy, Required
     * @param chainDepthRange the chain depth range, see PsidGroupPermissions for details, Required
     * @param issuerSigningAlgorithm the algorith used for signing and verifying the signature, Required
     * @param subjectKeypair The key pair to sign and verify this certificate, Required
     * @param encPublicKeyAlgorithm Algorithm used for encryption, null if no encryption key should be included
     * @param encPublicKey the public key for encryption, null if none
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public CertificateBase generateRootCA(String hostname,
                                          ValidityPeriod validityPeriod,
                                          GeographicRegion geographicRegionegion,
                                          int assuranceLevel,
                                          int confidenceLevel,
                                          int minChainDepth,
                                          int chainDepthRange,
                                          Signature.SignatureTypes issuerSigningAlgorithm,
                                          KeyPair subjectKeypair,
                                          SymmAlgorithm symmAlgorithm,
                                          BasePublicEncryptionKeyTypes encPublicKeyAlgorithm,
                                          PublicKey encPublicKey) throws IOException, NoSuchAlgorithmException, SignatureException
    {
        CertificateId id = new CertificateId(new Hostname(hostname));
        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);

        SubjectPermissions subjectPermissions = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.ALL, null);

        PsidGroupPermissions psidGroupPermissions =  new PsidGroupPermissions(subjectPermissions, minChainDepth, chainDepthRange, new EndEntityType(true, true));
        SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {psidGroupPermissions}); // certRequest permissions is absent

        //TODO VER MELHOR AS PERMISSOES psid -> etsi ts 102 966; ; ssp -> etsi ts 102 941
        PsidSsp permissionsCRL = new PsidSsp(new Psid(256), null); // permissions to sign CRL  (psid indicates app and ssp indicates permissions within that app, which is null if default)
        PsidSsp permissionsCTL = new PsidSsp(new Psid(36), null); // ITS-AID value to sign CTL not found in the standard ETSI TS 102 965 (update to the standard in preparation at the present time)
        PsidSsp[] values = {permissionsCRL, permissionsCTL};
        SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp(values);

        PublicEncryptionKey encryptionKey = null;
        if(encPublicKey != null && symmAlgorithm != null && encPublicKeyAlgorithm != null)
        {
            encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
        }

        PublicVerificationKey publicVerificationKey = new PublicVerificationKey(getPublicVerificationKeyType(issuerSigningAlgorithm), convertToPoint(issuerSigningAlgorithm, subjectKeypair.getPublic()));
        VerificationKeyIndicator verificationKeyIndicator = new VerificationKeyIndicator(publicVerificationKey);



        ToBeSignedCertificate toBeSignedCertificate = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0),  validityPeriod, geographicRegionegion, subjectAssurance,  appPermissions , certIssuePermissions, null, false, encryptionKey, verificationKeyIndicator);//To be signed data acording to ETSI profiles (ETSI103097 standard)

        return generateCertificate(toBeSignedCertificate,null, subjectKeypair, issuerSigningAlgorithm);
    }


    /**
     *
     * @param hostname
     * @param validityPeriod
     * @param region
     * @param subjectPermissions  indicate issuing permissions, i.e. permissions to sign an enrolment credential / authorization ticket with certain permissions
     * @param cracaid
     * @param crlSeries
     * @param assuranceLevel
     * @param confidenceLevel
     * @param minChainDepth
     * @param chainDepthRange
     * @param issuerSigningAlgorithm
     * @param signPublicKey
     * @param issuerCertificate
     * @param issuerCertificateKeyPair
     * @param symmAlgorithm
     * @param encPublicKeyAlgorithm
     * @param encPublicKey
     * @return
     * @throws IOException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     */
    public CertificateBase generateEnrollmentCa(String hostname,
                                                ValidityPeriod validityPeriod,
                                                GeographicRegion region,
                                                PsidSspRange[] subjectPermissions,
                                                byte[] cracaid,
                                                int crlSeries,
                                                int assuranceLevel,
                                                int confidenceLevel,
                                                int minChainDepth,
                                                int chainDepthRange,
                                                AlgorithmType issuerSigningAlgorithm,
                                                PublicKey signPublicKey, // the enrollment CA public key to be certified
                                                CertificateBase issuerCertificate,
                                                KeyPair issuerCertificateKeyPair,
                                                SymmAlgorithm symmAlgorithm,
                                                BasePublicEncryptionKeyTypes encPublicKeyAlgorithm,
                                                PublicKey encPublicKey) throws IOException, SignatureException, NoSuchAlgorithmException
    {
        CertificateId id = new CertificateId(new Hostname(hostname));

        SubjectPermissions sp;
        if(subjectPermissions == null){
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.ALL, null);
        }else{
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.EXPLICIT, new SequenceOfPsidSspRange(subjectPermissions));
        }

        PsidGroupPermissions pgp;
        pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(false, true));
        SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {pgp});

        // shall be used to indicate message signing permissions, i.e. permissions to sign certificate response messages contained in a EtsiTs103097Data.
        //TODO VER MELHOR AS PERMISSOES, psid -> etsi ts 102 966;
        PsidSsp SignResponsePermissions = new PsidSsp(new Psid(36), null); // permissions to sign certificate response messages. ITS-AID value to sign certificate response not found in the standard ETSI TS 102 965 (update to the standard in preparation t the present time)
        PsidSsp[] values = {SignResponsePermissions};
        SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp(values);

        PublicEncryptionKey encryptionKey = null;
        if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
            encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
        }
        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
        VerificationKeyIndicator vki;

        PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationKeyType(issuerSigningAlgorithm), convertToPoint(issuerSigningAlgorithm, signPublicKey));
        vki = new VerificationKeyIndicator(verifyKeyIndicator);

        ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, null, false, encryptionKey, vki);
        return generateCertificate(tbs, issuerCertificate, issuerCertificateKeyPair, issuerSigningAlgorithm);

    }

    /**
     *
     * @param hostname
     * @param validityPeriod
     * @param region
     * @param subjectPermissions  indicate issuing permissions, i.e. permissions to sign an enrolment credential / authorization ticket with certain permissions
     * @param cracaid
     * @param crlSeries
     * @param assuranceLevel
     * @param confidenceLevel
     * @param minChainDepth
     * @param chainDepthRange
     * @param issuerSigningAlgorithm
     * @param signPublicKey
     * @param issuerCertificate
     * @param issuerCertificateKeyPair
     * @param symmAlgorithm
     * @param encPublicKeyAlgorithm
     * @param encPublicKey
     * @return
     * @throws IOException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     */
    public CertificateBase generateAuthorizationAuthority(String hostname,
                                                ValidityPeriod validityPeriod,
                                                GeographicRegion region,
                                                PsidSspRange[] subjectPermissions,
                                                byte[] cracaid,
                                                int crlSeries,
                                                int assuranceLevel,
                                                int confidenceLevel,
                                                int minChainDepth,
                                                int chainDepthRange,
                                                AlgorithmType issuerSigningAlgorithm,
                                                PublicKey signPublicKey,
                                                CertificateBase issuerCertificate,
                                                KeyPair issuerCertificateKeyPair,
                                                SymmAlgorithm symmAlgorithm,
                                                BasePublicEncryptionKeyTypes encPublicKeyAlgorithm,
                                                PublicKey encPublicKey) throws IOException, SignatureException, NoSuchAlgorithmException
    {
        CertificateId id = new CertificateId(new Hostname(hostname));

        SubjectPermissions sp;
        if(subjectPermissions == null){
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.ALL, null);
        }else{
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.EXPLICIT, new SequenceOfPsidSspRange(subjectPermissions));
        }

        PsidGroupPermissions pgp;
        pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(true, false));
        SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {pgp});

        // shall be used to indicate message signing permissions, i.e. permissions to sign certificate response messages contained in a EtsiTs103097Data.
        //TODO VER MELHOR AS PERMISSOES, psid -> etsi ts 102 966;
        PsidSsp SignResponsePermissions = new PsidSsp(new Psid(36), null); // permissions to sign certificate response messages. ITS-AID value to sign certificate response not found in the standard ETSI TS 102 965 (update to the standard in preparation t the present time)
        PsidSsp[] values = {SignResponsePermissions};
        SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp(values);

        PublicEncryptionKey encryptionKey = null;
        if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
            encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
        }
        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
        VerificationKeyIndicator vki;

        PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationKeyType(issuerSigningAlgorithm), convertToPoint(issuerSigningAlgorithm, signPublicKey));
        vki = new VerificationKeyIndicator(verifyKeyIndicator);

        ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, null, false, encryptionKey, vki);
        return generateCertificate(tbs, issuerCertificate, issuerCertificateKeyPair, issuerSigningAlgorithm);

    }
}
