package com.multicert.v2x.datastructures.message.encrypteddata;


import com.multicert.v2x.asn1.coer.COERSequenceOf;

public class SequenceOfRecipientInfo extends COERSequenceOf
{
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRecipientInfo(RecipientInfo[] values)
    {
		super(values);
	}

	/**
	 * Constructor used when decoding
	 */
	public SequenceOfRecipientInfo()
    {
		super(new RecipientInfo());
	}
}
