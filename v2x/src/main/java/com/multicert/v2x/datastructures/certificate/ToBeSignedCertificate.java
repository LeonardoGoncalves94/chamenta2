package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COERNull;
import com.multicert.v2x.asn1.coer.COERSequence;
import com.multicert.v2x.datastructures.base.*;

import java.io.*;

public class ToBeSignedCertificate extends COERSequence
{
    protected static final int SEQUENCE_SIZE = 12;

    protected static final int ID = 0;
    protected static final int CARCA_ID = 1;
    protected static final int CRL_SERIES = 2;
    protected static final int VALIDITY_PERIOD = 3;
    protected static final int REGION = 4;
    protected static final int ASSURANCE_LEVEL = 5;
    protected static final int APP_PERMISSIONS = 6;
    protected static final int CERT_ISSUE_PERMISSIONS = 7;
    protected static final int CERT_REQUEST_PERMISSIONS = 8;
    protected static final int CAN_REQUEST_ROLLOVER = 9;
    protected static final int ECRYPTION_KEY = 10;
    protected static final int VERIFY_KEY_INDICATOR = 11;


    /**
     * Constructor used when encoding
     */
    public ToBeSignedCertificate(CertificateId id, HashedId3 cracaId, CrlSeries crlSeries,
                                 ValidityPeriod validityPeriod, GeographicRegion region, SubjectAssurance assuranceLevel,
                                 SequenceOfPsidSsp appPermissions, SequenceOfPsidGroupPermissions certIssuePermissions,
                                 SequenceOfPsidGroupPermissions certRequestPermissions, boolean canRequestRollover,
                                 PublicEncryptionKey encryptionKey, VerificationKeyIndicator verifyKeyIndicator) throws IOException{
        super(SEQUENCE_SIZE);
        createSequence();
        setComponentValue(ID, id);
        setComponentValue(CARCA_ID, cracaId);
        setComponentValue(CRL_SERIES, crlSeries);
        setComponentValue(VALIDITY_PERIOD, validityPeriod);
        setComponentValue(REGION, region);
        setComponentValue(ASSURANCE_LEVEL, assuranceLevel);
        setComponentValue(APP_PERMISSIONS, appPermissions);
        setComponentValue(CERT_ISSUE_PERMISSIONS, certIssuePermissions);
        setComponentValue(CERT_REQUEST_PERMISSIONS, certRequestPermissions);
        if(canRequestRollover){
            setComponentValue(CAN_REQUEST_ROLLOVER, new COERNull());
        }
        setComponentValue(ECRYPTION_KEY, encryptionKey);
        setComponentValue(VERIFY_KEY_INDICATOR, verifyKeyIndicator);
    }


    /**
     * Constructor used when decoding
     */
    public ToBeSignedCertificate()throws IOException
    {
        super(12);
        createSequence();
    }

    private void createSequence() throws IOException
    {
        addComponent(ID, false, new CertificateId(), null);
        addComponent(CARCA_ID, false, new HashedId3(), null);
        addComponent(CRL_SERIES, false, new CrlSeries(), null);
        addComponent(VALIDITY_PERIOD, false, new ValidityPeriod(), null);
        addComponent(REGION, true, new GeographicRegion(), null);
        addComponent(ASSURANCE_LEVEL, true, new SubjectAssurance(), null);
        addComponent(APP_PERMISSIONS, true, new SequenceOfPsidSsp(), null);
        addComponent(CERT_ISSUE_PERMISSIONS, true, new SequenceOfPsidGroupPermissions(), null);
        addComponent(CERT_REQUEST_PERMISSIONS, true, new SequenceOfPsidGroupPermissions(), null);
        addComponent(CAN_REQUEST_ROLLOVER, true, new COERNull(), null);
        addComponent(ECRYPTION_KEY, true, new PublicEncryptionKey(), null);
        addComponent(VERIFY_KEY_INDICATOR, false, new VerificationKeyIndicator(), null);

    }

    /**
     * Encodes the ToBeSignedCertificate in a byte array (to be used in the signature process).
     *
     * @return return the encoded ToBeSignedCertificate as a byte[]
     * @throws IOException if encoding problems of the data occurred.
     */
    public byte[] getEncoded() throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }

    /**
     * @return the id, required
     */
    public CertificateId getId()
    {
        return (CertificateId) getComponentValue(ID);
    }

    /**
     * @return the cracaId, required
     */
    public HashedId3 getCracaId()
    {
        return (HashedId3) getComponentValue(CARCA_ID);
    }

    /**
     * @return the crlSeries, required
     */
    public CrlSeries getCrlSeries()
    {
        return (CrlSeries) getComponentValue(CRL_SERIES);
    }

    /**
     * @return the validityPeriod, required
     */
    public ValidityPeriod getValidityPeriod()
    {
        return (ValidityPeriod) getComponentValue(VALIDITY_PERIOD);
    }

    /**
     * @return the region, optional
     */
    public GeographicRegion getRegion()
    {
        return (GeographicRegion) getComponentValue(REGION);
    }

    /**
     * @return the assuranceLevel, optional
     */
    public SubjectAssurance getAssuranceLevel()
    {
        return (SubjectAssurance) getComponentValue(ASSURANCE_LEVEL);
    }

    /**
     * @return the appPermissions, optional
     */
    public SequenceOfPsidSsp getAppPermissions()
    {
        return (SequenceOfPsidSsp) getComponentValue(APP_PERMISSIONS);
    }

    /**
     * @return the certIssuePermissions, optional
     */
    public SequenceOfPsidGroupPermissions getCertIssuePermissions()
    {
        return (SequenceOfPsidGroupPermissions) getComponentValue(CERT_ISSUE_PERMISSIONS);
    }

    /**
     * @return the certRequestPermissions, always ABSENT
     */
    public SequenceOfPsidGroupPermissions getCertRequestPermissions()
    {
        return (SequenceOfPsidGroupPermissions) getComponentValue(CERT_REQUEST_PERMISSIONS);
    }

    /**
     * @return the canRequestRollover, always ABSENT
     */
    public boolean isCanRequestRollover()
    {
        return getComponentValue(CAN_REQUEST_ROLLOVER) != null;
    }

    /**
     * @return the encryptionKey, optional
     */
    public PublicEncryptionKey getEncryptionKey()
    {
        return (PublicEncryptionKey) getComponentValue(ECRYPTION_KEY);
    }

    /**
     * @return the verifyKeyIndicator, required
     */
    public VerificationKeyIndicator getVerifyKeyIndicator()
    {
        return (VerificationKeyIndicator) getComponentValue(VERIFY_KEY_INDICATOR);
    }

}
