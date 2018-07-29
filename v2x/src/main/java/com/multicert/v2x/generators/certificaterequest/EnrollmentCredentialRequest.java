package com.multicert.v2x.generators.certificaterequest;


import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.*;
import com.multicert.v2x.datastructures.certificate.CertificateBase;
import com.multicert.v2x.datastructures.certificate.CertificateId;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.CertificateSubjectAttributes;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.InnerEcRequest;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.PublicKeys;
import com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941Data;
import com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941DataContent;
import com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941DataContent.*;
import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo;
import com.multicert.v2x.datastructures.message.encrypteddata.SequenceOfRecipientInfo;
import com.multicert.v2x.datastructures.message.secureddata.*;

import com.multicert.v2x.generators.certificate.CertificateGenerator;
import com.multicert.v2x.generators.message.SecuredDataGenerator;


import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.util.Date;

/**
 * This class generates an Enrollment Certificate request as specified in ETSI 102-941, Section 6.2.3.2.1 standard
 *
 */
public class EnrollmentCredentialRequest extends SecuredDataGenerator
{

    CertificateGenerator certificateGenerator; // needed to support some operations in the createInnerECRequest method
    SecretKey vehicleSecretKey; //the vehicle's secret key to be encrypt the request and  shared with the enrollmet authority to encrypt the response


    public EnrollmentCredentialRequest(CryptoHelper cryptoHelper, boolean isCompressed)
    {
        super(cryptoHelper);
        certificateGenerator = new CertificateGenerator(cryptoHelper, isCompressed);
    }

    /**
     * Method that generates the first enrollment certificate request of a given ITS-S according to Etsi102 0941 standard
     * @param itsID The identifier of the requesting ITS-S, more details in InnerEcRequest. Required
     * @param verificationKeyPair The verification key to be certified in the enrollment certificate. Required.
     * @param signingAlgorithm The algorithm used for signing and verification by the ITS-S. Required.
     * @param hostname The name of the ITS-S. Required.
     * @param validityPeriod The Validity period of the requested enrollment certificate. Optional.
     * @param geographicRegion The Validity region of the requested enrollment certificate. Optional.
     * @param assuranceLevel The assurance level of the requested enrollment certificate. Required
     * @param confidenceLevel The Confidence level of the requested enrollment certificate. Required.
     * @return The Enrollment certificate request signed and encrypted
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public Ieee1609Dot2Data generateEcRequenst(String itsID, KeyPair verificationKeyPair, AlgorithmType signingAlgorithm, String hostname,
                                               ValidityPeriod validityPeriod, GeographicRegion geographicRegion,
                                               int assuranceLevel, int confidenceLevel, CertificateBase EnrollmentAuthorityCertificate) throws IOException, GeneralSecurityException
    {
        PublicKey verificationKey = verificationKeyPair.getPublic();
        PrivateKey signingKey = verificationKeyPair.getPrivate();

        InnerEcRequest innerEcRequest = createInnerECRequest(itsID, verificationKey, signingAlgorithm, hostname, validityPeriod, geographicRegion, assuranceLevel, confidenceLevel);

        Ieee1609Dot2Data InnerECRequestSignedForPOP = createRequestSignedData(innerEcRequest.getEncoded(),signingKey , signingAlgorithm); // this data structure is self signed by the ITS-S to prove possession of the generated verification key pair

        EtsiTs102941Data etsiTs102941Data = createEtsiTs102941Data(InnerECRequestSignedForPOP);

        Ieee1609Dot2Data outerEcRequest = createRequestSignedData(etsiTs102941Data.getEncoded(),signingKey, signingAlgorithm);

        Ieee1609Dot2Data encryptedEcRequest = createRequestEncryptedData(outerEcRequest, EnrollmentAuthorityCertificate);

        return encryptedEcRequest;
    }

    public Ieee1609Dot2Data generateEcRequestReEnrollment(CertificateBase validEnrollmentCertificate)
    {
        return null;
    }

    /**
     * Method that created the InnerEcRequest structure of the enrollment certificate request.
     */
    public InnerEcRequest createInnerECRequest(String itsID, PublicKey verificationKey, AlgorithmType signingAlgorithm, String hostname,
                                               ValidityPeriod validityPeriod, GeographicRegion geographicRegionegion, int assuranceLevel,
                                               int confidenceLevel) throws IOException
    {
        PublicVerificationKey publicVerificationKey = new PublicVerificationKey(certificateGenerator.getPublicVerificationKeyType(signingAlgorithm), certificateGenerator.convertToPoint(signingAlgorithm, verificationKey)); // type and key
        PublicKeys publicKeys = new PublicKeys(publicVerificationKey, null); // no encryption key, only the verification key to be certified in the Enrollment credential

        CertificateId name = new CertificateId(new Hostname(hostname));

        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);

        CertificateSubjectAttributes requestedSubjectAttributes = new CertificateSubjectAttributes(name, validityPeriod, geographicRegionegion, subjectAssurance, null, null ); //app permissions and certificate issue permissions are absent because enrollment certificates do not express them.

       return new InnerEcRequest(itsID, publicKeys, requestedSubjectAttributes);
    }

    /**
     * This method creates the signed data structures of the certificate request:
     * The inner signed data is the InnerECRequestSignedForPOP structure of the certificate request. The signature is computed by the ITS-S over the innerEcRequest using the private key corresponding to the new verification key pair prove its possession
     * The outer signed data structure, which  the signature is computed over the EtsiTs102941Data structure using the private key corresponding to the new verification key pair in the case of the first enrollment. Or the private key corresponding to the current valid enrollment certificate in the case of re-enrollment
     * @param message the data to be signed. Required.
     * @param privateKey the private key to sign the message
     * @param signingAlgorithm the digital signature algorithm
     *
     * @return the Signed data structure
     */
    public Ieee1609Dot2Data createRequestSignedData(byte[] message, PrivateKey privateKey, AlgorithmType signingAlgorithm) throws IOException, NoSuchAlgorithmException, SignatureException
    {
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_256;
        HeaderInfo headerInfo = new HeaderInfo(new Psid(36),new Time64(new Date()),null, null, null, null,null); // the Psid element of the header is set to "CA Basic Service" because the "secured certificate request" cannot be found in ETSI TS 102 965 at the present time.
        SignerIdentifier signerIdentifier = new SignerIdentifier(); // set to "self"
        return createSignedData(hashAlgorithm, message, headerInfo, signerIdentifier, privateKey, signingAlgorithm);
    }

    /**
     * This method creates the EtsiTs102941Data structure of the enrollment certificate request.
     * @return
     */
    public EtsiTs102941Data createEtsiTs102941Data(Ieee1609Dot2Data InnerECRequestSignedForPOP) throws IOException
    {
         EtsiTs102941DataContent dataContent = new EtsiTs102941DataContent(EtsiTs102941DataContentTypes.ENROLLMENT_REQUEST, InnerECRequestSignedForPOP);
         return new EtsiTs102941Data(dataContent);
    }

    /**
     * This metdo creates the encrypted data structure of the Ec request
     * @param EaCert specifies the certificate of the enrollment CA which this EC request will be encrypted to
     * @param outerEcRequest the data to be encrypted
     * @return the encrypted EC request
     * @throws IOException
     */
    public Ieee1609Dot2Data createRequestEncryptedData(Ieee1609Dot2Data outerEcRequest, CertificateBase EaCert) throws IOException, GeneralSecurityException
    {
        if(EaCert.getTbsCert().getEncryptionKey() == null){
            throw new IllegalArgumentException("Error encrypting EC request: The EA certificate cannot be used as encryption receipient, no public encryption key found.");
        }

        vehicleSecretKey = getSecretKey(SymmAlgorithm.AES_128_CCM);
        RecipientInfo[] recipients = {getRecipientInfo(EaCert, vehicleSecretKey)};
        SequenceOfRecipientInfo sequenceOfRecipients = new SequenceOfRecipientInfo(recipients);

      return createEncryptedData(sequenceOfRecipients, outerEcRequest.getEncoded(), SymmAlgorithm.AES_128_CCM, vehicleSecretKey);
    }

    /**
     * Method to return the encryption key to the vehicle
     */
    public SecretKey getVehicleSecretKey()
    {
        return vehicleSecretKey;
    }
}
