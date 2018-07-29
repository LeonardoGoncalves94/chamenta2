package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERInteger;

import java.math.BigInteger;

/**
 * This class represents the Psid, which is an int value that identifies applications
 */
public class Psid extends COERInteger
{
    /**
     * Constructor used when encoding
     *
     * @param psidValue the integer value of the psid
     */
    public Psid(long psidValue)
    {
        super(BigInteger.valueOf(psidValue),BigInteger.ZERO,null);
    }

    /**
     * Constructor used when decoding
     */
    public Psid()
    {
        super(BigInteger.ZERO,null);
    }
}
