package com.multicert.v2x.datastructures.base;

/**
 * HashedId8 is an hashed based identifier for other data structures. The HashedId38for a given data structure is calculated
 * by calculating the SHA-256 hash of the encoded data structure and then taking the eight least significant bytes of
 * the digest.
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 *
 */
public class HashedId8 extends HashedId
{
    private static final int HASHED_ID_LENGTH = 8;

    /**
     * Constructor used for constructing an HashedId3 from a full hash byte array.
     *
     * @param fullDigest byte array that contains the full digest.
     */
    public HashedId8(byte[] fullDigest)
    {
        super(fullDigest, HASHED_ID_LENGTH);
    }

    /**
     * Constructor used when decoding.
     *
     */
    public HashedId8()
    {
        super(HASHED_ID_LENGTH);
    }
}
