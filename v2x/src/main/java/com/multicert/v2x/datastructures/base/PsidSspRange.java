package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERSequence;

import java.io.IOException;

public class PsidSspRange extends COERSequence
{
    private static final int PSID = 0;
    private static final int SSPRANGE = 1;

    /**
     * Constructor used when encoding
     */
    public PsidSspRange(Psid psid, SspRange ssprange) throws IOException
    {
        super(2);
        createSequence();
        setComponentValue(PSID, psid);
        setComponentValue(SSPRANGE, ssprange);
    }

    /**
     * Constructor used when decoding
     */
    public PsidSspRange()
    {
        super(2);
        createSequence();
    }

    private void createSequence()
    {
        addComponent(PSID, false, new Psid(), null);
        addComponent(SSPRANGE, true, new SspRange(), null);
    }
}
