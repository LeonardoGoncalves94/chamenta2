package com.multicert.v2x.generators.certificate;


import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.certificate.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * This class generates the authorization tickets which will be used by the vehicles to authenticate V2X messages
 *
 */
public class AuthorizationTicketGenerator extends CertificateGenerator
{
    public AuthorizationTicketGenerator(CryptoHelper cryptoHelper, boolean isCompressed)
    {
        super(cryptoHelper, isCompressed);
    }

    /**
     *
     * @param hostname
     * @param validityPeriod
     * @param region
     * @param appPermissions used to indicate message signing permissions, i.e. permissions to sign v2x messages
     * @param certRequestPermissions
     * @param cracaid
     * @param crlSeries
     * @param assuranceLevel
     * @param confidenceLevel
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
    public CertificateBase generateAuthorizationTicket(String hostname,
                                                        ValidityPeriod validityPeriod,
                                                        GeographicRegion region,
                                                        PsidSsp[] appPermissions,
                                                        PsidSspRange[] certRequestPermissions,
                                                        byte[] cracaid,
                                                        int crlSeries,
                                                        int assuranceLevel,
                                                        int confidenceLevel,
                                                        AlgorithmType issuerSigningAlgorithm,
                                                        PublicKey signPublicKey,
                                                        CertificateBase issuerCertificate,
                                                        KeyPair issuerCertificateKeyPair,
                                                        SymmAlgorithm symmAlgorithm,
                                                        BasePublicEncryptionKey.BasePublicEncryptionKeyTypes encPublicKeyAlgorithm,
                                                        PublicKey encPublicKey) throws IOException, SignatureException, NoSuchAlgorithmException
    {
        CertificateId id = new CertificateId(new Hostname(hostname));

        if(appPermissions == null)
        {
            throw new IllegalArgumentException("Error generating authorization ticket: app permissions should not be null");
        }
        SequenceOfPsidSsp appPerms = new SequenceOfPsidSsp(appPermissions);

        SubjectPermissions sp;
        if(certRequestPermissions == null){
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.ALL, null);
        }else{
            sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsTypes.EXPLICIT, new SequenceOfPsidSspRange(certRequestPermissions));
        }

        PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 0, 0, new EndEntityType(true, false));

        SequenceOfPsidGroupPermissions certReqPermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {pgp});


        PublicEncryptionKey encryptionKey = null;
        if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
            encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
        }
        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
        VerificationKeyIndicator verificationKeyIndicator;

        PublicVerificationKey publicVerificationKey = new PublicVerificationKey(getPublicVerificationKeyType(issuerSigningAlgorithm), convertToPoint(issuerSigningAlgorithm, signPublicKey));
        verificationKeyIndicator = new VerificationKeyIndicator(publicVerificationKey);

        ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, appPerms, null, certReqPermissions, false, encryptionKey, verificationKeyIndicator);

        return generateCertificate(tbs, issuerCertificate, issuerCertificateKeyPair, issuerSigningAlgorithm);
    }
}
