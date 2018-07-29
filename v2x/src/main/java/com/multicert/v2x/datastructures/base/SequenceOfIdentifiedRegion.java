package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERSequenceOf;

/**
 * A sequence of IdentifiedRegion objects
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 *
 */
public class SequenceOfIdentifiedRegion extends COERSequenceOf
{
    /**
     * Constructor used when encoding
     *
     */
    public SequenceOfIdentifiedRegion(IdentifiedRegion[] values)
    {
        super(values);
    }

    /**
     * Constructor used when decoding
     */
    public SequenceOfIdentifiedRegion()
    {
        super(new IdentifiedRegion());
    }
}
