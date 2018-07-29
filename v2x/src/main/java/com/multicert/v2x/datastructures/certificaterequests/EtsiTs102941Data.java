package com.multicert.v2x.datastructures.certificaterequests;

import com.multicert.v2x.asn1.coer.COERInteger;
import com.multicert.v2x.asn1.coer.COERSequence;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class EtsiTs102941Data extends COERSequence
{
    private static final int CURRENT_VERSION = 1;
    private static final int SEQUENCE_SIZE = 2;
    private static final int VERSION = 0;
    private static final int CONTENT = 1;

    /**
     * Constructor used when encoding a EtsiTs102941Data structure with default version (v1)
     */
    public EtsiTs102941Data(EtsiTs102941DataContent dataContent) throws IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();
        setComponentValue(VERSION, new COERInteger(CURRENT_VERSION));
        setComponentValue(CONTENT, dataContent);
    }

    /**
     * Constructor used when encoding
     */
    public EtsiTs102941Data(int version, EtsiTs102941DataContent dataContent) throws IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();
        setComponentValue(VERSION, new COERInteger(version));
        setComponentValue(CONTENT, dataContent);
    }

    /**
     * Constructor used when decoding
     */
    public EtsiTs102941Data()
    {
        super(SEQUENCE_SIZE);
        createSequence();
    }

    public byte[] getEncoded() throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }

    public void createSequence()
    {
        addComponent(VERSION, false, new COERInteger(), null);
        addComponent(CONTENT, false, new EtsiTs102941DataContent(), null);
    }
}
