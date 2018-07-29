package com.multicert.v2x.datastructures.certificate;


import com.multicert.v2x.asn1.coer.COERSequenceOf;
import java.io.IOException;

public class SequenceOfCertificate extends COERSequenceOf
{
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfCertificate() throws IOException
	{
		super(new CertificateBase());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfCertificate(CertificateBase[] values)
	{
		super(values);
	}
}
