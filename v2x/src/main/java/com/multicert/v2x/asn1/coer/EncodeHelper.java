package com.multicert.v2x.asn1.coer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

public class EncodeHelper
{
    /**
     * Method that inserts zeroes at the beginning of a byte array
     *
     * @param data the byte array to transform
     * @param size the size that the array will have after transformation
     * @return the transformed array
     * @return the array of bytes
     */
    public static byte[] padWithZeroes(byte[] data, int size)
    {
        if(data == null){
            return null;
        }
        if(data.length < size)
        {
            byte[] result = new byte[size];
            System.arraycopy(data, 0, result, size-data.length, data.length);
            data = result;
        }
        return data;
    }

    public static void writeFixedFieldSizeKey(int size, OutputStream out, BigInteger keyValue) throws UnsupportedOperationException, IOException
    {
        byte[] valueByteArray = keyValue.toByteArray();

        if(valueByteArray.length < size) //TODO ver melhor
        {
            out.write(new byte[size - valueByteArray.length]);
        }
        if(valueByteArray.length > size)
        {
            out.write(valueByteArray, valueByteArray.length-size, size);
        }
        else
        {
            out.write(valueByteArray);
        }
    }



}
