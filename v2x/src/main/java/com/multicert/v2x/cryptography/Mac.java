package com.multicert.v2x.cryptography;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;

public class Mac implements org.bouncycastle.crypto.Mac
{
    Digest digest;
    HMac hMac;
    int tBytes;

    public Mac(Digest digest, int tBits)
    {
        if(tBits % 8 != 0)
        {
            throw new IllegalArgumentException("Error creating MAC: tBits must be a multiple of 8");
        }
        tBytes = tBits/8;
        hMac = new HMac(digest);
    }

    @Override
    public void init(CipherParameters params) throws IllegalArgumentException
    {
        hMac.init(params);

    }

    @Override
    public String getAlgorithmName()
    {
        return digest.getAlgorithmName();
    }

    @Override
    public int getMacSize()
    {
        return tBytes;
    }

    @Override
    public void update(byte in) throws IllegalStateException
    {
        hMac.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len)
            throws DataLengthException, IllegalStateException
    {
        hMac.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) throws DataLengthException,
            IllegalStateException {

        byte[] tempOut = new byte[hMac.getMacSize()];
        int retval = hMac.doFinal(tempOut, outOff);
        System.arraycopy(tempOut, 0, out, 0, tBytes);
        return retval;
    }

    @Override
    public void reset()
    {
        hMac.reset();
    }
}
