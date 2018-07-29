package com.multicert.v2x.datastructures.message.secureddata;

import com.multicert.v2x.asn1.coer.*;
import com.multicert.v2x.datastructures.base.HashAlgorithm;


public class HashedData extends COERChoice
{

	public enum HashedDataChoices implements COERChoiceEnumeration
	{
		SHA256_HASHED_DATA;

		public int myOrdinal()
		{
			return this.ordinal();
		}

		@Override
		public COEREncodable getEncodableType()
		{
			return new COEROctetString(32,32);
		}
	}
	
	/**
	 * Constructor used when encoding the type SHA256_HASHED_DATA
	 */
	public HashedData(HashedDataChoices type, byte[] hash) throws IllegalArgumentException
    {
		super(type, new COEROctetString(hash, 32, 32));
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public HashedData()
    {
		super(HashedDataChoices.class);
	}
		
	/**
	 * Returns the type of id.
	 */
	public HashedDataChoices getType()
    {
		return (HashedDataChoices) choice;
	}



}
