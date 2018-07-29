package com.multicert.v2x.asn1.coer;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * COER encoding of a sequence-of following the section  17 of the ISO/IEC 8825-7:2015 standard
 *
 * The encoding of a sequence-of value shall consist of a quantity field followed by the encodings of the occurrences of the component (must be of the same type)
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 */
public class COERSequenceOf implements COEREncodable
{
    private COEREncodable[] values;
    COEREncodable emptyValue;


    /**
     * Constructor used when encoding
     */
    public COERSequenceOf(COEREncodable[] values)
    {
        this.values = values;
    }

    /**
     * Constructor used when decoding
     */
    public COERSequenceOf(COEREncodable emptyValue)
    {
        this.emptyValue = emptyValue;
    }

    @Override
    public void encode(DataOutputStream out) throws IOException
    {
        COERInteger length = new COERInteger(BigInteger.valueOf(values.length), BigInteger.ZERO, null);
        length.encode(out);
        for(COEREncodable v : values)
        {
            v.encode(out);
        }
    }

    @Override
    public void decode(DataInputStream in) throws IOException
    {

        COERInteger length = new COERInteger(BigInteger.ZERO, null);
        length.decode(in);
        values = new COEREncodable[length.getValue().intValue()];
        for(int i = 0; i < (int)length.getValueAsLong(); i ++)
        {
            values[i] = emptyValue; //TODO Ver no c2c...
            values[i].decode(in);
        }
    }

    public COEREncodable[] getValues()
    {
        return values;
    }
}
