package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERSequenceOf;
import com.multicert.v2x.datastructures.base.PsidSsp;

/**
 * A sequence of PsidSsp
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 *
 */
public class SequenceOfPsidSsp extends COERSequenceOf
{
    /**
     * Constructor used when encoding
     *
     */
    public SequenceOfPsidSsp(PsidSsp[] values)
    {
        super(values);
    }

    /**
     * Constructor used when decoding
     *
     */
    public SequenceOfPsidSsp()
    {
        super(new PsidSsp());
    }
}
