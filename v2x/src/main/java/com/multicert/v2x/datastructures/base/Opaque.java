package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COEROctetString;

public class Opaque extends COEROctetString
{
    /**
     * Constructor used when encoding
     */
    public Opaque(byte[] data)
    {
        super(data);
    }

    /**
     * Constructor used when decoding
     */
    public Opaque()
    {
        super();
    }

}
