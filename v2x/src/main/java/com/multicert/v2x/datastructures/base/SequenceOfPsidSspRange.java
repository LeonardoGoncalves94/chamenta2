package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERSequenceOf;

public class SequenceOfPsidSspRange extends COERSequenceOf
{
    /**
     * Contructor used when encoding
     */
    public SequenceOfPsidSspRange(PsidSspRange[] values)
    {
        super(values);
    }

    /**
     * Contructor used when decoding
     */
    public SequenceOfPsidSspRange()
    {
        super(new PsidSspRange());
    }
}
