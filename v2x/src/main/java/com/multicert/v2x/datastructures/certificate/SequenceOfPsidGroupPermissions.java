package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COERSequenceOf;

public class SequenceOfPsidGroupPermissions extends COERSequenceOf
{
    /**
     * Constructor used when encoding
     */
    public SequenceOfPsidGroupPermissions (PsidGroupPermissions[] values)
    {
        super(values);
    }

    /**
     * Constructor used when decoding
     *
     */
    public SequenceOfPsidGroupPermissions()
    {
        super(new PsidGroupPermissions());
    }
}
