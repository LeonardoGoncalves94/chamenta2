package com.multicert.v2x.datastructures.message.secureddata;

import com.multicert.v2x.asn1.coer.COERSequence;
import com.multicert.v2x.datastructures.base.Uint8;


import java.io.*;



public class Ieee1609Dot2Data extends COERSequence
{
	
	public static final int SEQUENCE_SIZE = 2;
    public static final int CURRENT_VERSION = 3;
	
	private static final int PROTOCOLVERSION = 0;
	private static final int CONTENT = 1;

    /**
     * Constructor used when encoding
     */
    public Ieee1609Dot2Data(int protocolVersion, Ieee1609Dot2Content content) throws IOException
    {
        super(SEQUENCE_SIZE);
        createSequence();
        setComponentValue(PROTOCOLVERSION, new Uint8(protocolVersion));
        setComponentValue(CONTENT, content);
    }

	/**
	 * Constructor used when encoding using default protocol version (3)
	 */
	public Ieee1609Dot2Data(Ieee1609Dot2Content content) throws IOException
	{
		this(CURRENT_VERSION, content);
	}

	/**
	 * Constructor used when decoding
	 */
	public Ieee1609Dot2Data(){
		super(SEQUENCE_SIZE);
		createSequence();
	}

	/**
	 * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
	 * @param encodedData the encoded Ieee1609Dot2Data
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public Ieee1609Dot2Data(byte[] encodedData) throws IOException{
		super(SEQUENCE_SIZE);
		createSequence();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 * Encodes the Ieee1609Dot2Data as a byte array to be used for signing.
	 *
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();		
	}
	
	private void createSequence(){
		addComponent(PROTOCOLVERSION, false, new Uint8(), null);
		addComponent(CONTENT, false, new Ieee1609Dot2Content(), null);
	}

    /**
     *
     * @return protocolVersion
     */
    public int getProtocolVersion(){
        return (int) ((Uint8) getComponentValue(PROTOCOLVERSION)).getValueAsLong();
    }

    /**
     *
     * @return content
     */
    public Ieee1609Dot2Content getContent(){
        return (Ieee1609Dot2Content) getComponentValue(CONTENT);
    }

}
