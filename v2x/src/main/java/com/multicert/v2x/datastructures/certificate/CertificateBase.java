package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COEREnumeration;
import com.multicert.v2x.asn1.coer.COERSequence;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.base.Uint8;


import java.io.*;

/**
 * Only supports explicit certificates
 */
public class CertificateBase extends COERSequence
{
    protected static final int SEQUENCE_SIZE = 5;
    protected static final int CURRENT_VERSION = 3; // specifies the current protocol version of the certificate

    protected static final int VERSION = 0;
    protected static final int TYPE = 1;
    protected static final int ISSUER = 2;
    protected static final int TOBESIGNED = 3;
    protected static final int SIGNATURE = 4;

    /**
    * Main constructor for initializing the certificate
    */
    public CertificateBase(int version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSigned, Signature signature) throws IllegalArgumentException, IOException
    {
       super(SEQUENCE_SIZE);
       createSequence();

       if(signature == null)
       {
           throw new IllegalArgumentException("Error encoding certificate: Signature must not be empty");
       }
       if(toBeSigned.getVerifyKeyIndicator().getType() != VerificationKeyIndicator.VerificationKeyIndicatorTypes.VERIFICATION_KEY)
       {
           throw new IllegalArgumentException("Error encoding certificate: Explicit certificates must have a verification key");
       }

       setComponentValue(VERSION,new Uint8(version));
       setComponentValue(TYPE,new COEREnumeration(CertificateType.explicit));
       setComponentValue(ISSUER, issuer);
       setComponentValue(TOBESIGNED, toBeSigned);
       setComponentValue(SIGNATURE, signature);

    }

    /**
     * Main constructor for initializing the certificate with c default urrent version
     */
    public CertificateBase( IssuerIdentifier issuer, ToBeSignedCertificate toBeSigned, Signature signature) throws IllegalArgumentException, IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();

        if(signature == null)
        {
            throw new IllegalArgumentException("Error encoding certificate: Signature must not be empty");
        }
        if(toBeSigned.getVerifyKeyIndicator().getType() != VerificationKeyIndicator.VerificationKeyIndicatorTypes.VERIFICATION_KEY)
        {
            throw new IllegalArgumentException("Error encoding certificate: Explicit certificates must have a verification key");
        }

        setComponentValue(VERSION,new Uint8(CURRENT_VERSION));
        setComponentValue(TYPE,new COEREnumeration(CertificateType.explicit));
        setComponentValue(ISSUER, issuer);
        setComponentValue(TOBESIGNED, toBeSigned);
        setComponentValue(SIGNATURE, signature);

    }

    /**
     * Constructor used when decoding
     */
    public CertificateBase() throws IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();
    }

    /**
     * Constructor used for decoding a certificate from its encoded (triggers the decoding of all certificate fields)
     *
     * @param encoded The encoded certificate base
     */
    public CertificateBase (byte[] encoded) throws IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encoded));
        decode(dis);
    }

    /**
     * Method used for encoding a certificate base (triggers the encoding of all certificate fields)
     *
     * @return the encoded certificate base
     */
    public byte[] getEncoded() throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }

    public ToBeSignedCertificate getTbsCert()
    {
        return (ToBeSignedCertificate) getComponentValue(TOBESIGNED);
    }

    private void createSequence()throws IOException
    {
        addComponent(VERSION, false, new Uint8(), null);
        addComponent(TYPE, false, new COEREnumeration(CertificateType.class), null);
        addComponent(ISSUER, false, new IssuerIdentifier(), null);
        addComponent(TOBESIGNED, false, new ToBeSignedCertificate(), null);
        addComponent(SIGNATURE, true, new Signature(), null);
    }


}
