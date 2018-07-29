package com.multicert.v2x.datastructures.message.secureddata;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.datastructures.base.Opaque;
import com.multicert.v2x.datastructures.message.encrypteddata.EncryptedData;

import java.io.IOException;


public class Ieee1609Dot2Content extends COERChoice
{

	
	public enum Ieee1609Dot2ContentChoices implements COERChoiceEnumeration
    {
		UNSECURED_DATA,
		SIGNED_DATA,
		ENCRYPTED_DATA,
		SIGNED_CERTIFICATE_REQUEST;

		public int myOrdinal()
        {
            return this.ordinal();
        }

		@Override
		public COEREncodable getEncodableType()
		{
			switch (this)
			{
				case SIGNED_DATA:
					return new SignedData();
				case ENCRYPTED_DATA:
					return new EncryptedData();
				default:
					return new Opaque();

			}
		}
	}
	
	/**
	 * Constructor used when encoding the types UNSECURED_DATA or SIGNED_CERTIFICATE_REQUEST
	 */
	public Ieee1609Dot2Content(Ieee1609Dot2ContentChoices type, Opaque data) throws IllegalArgumentException{
		super(type, data);
	}
	
	/**
	 * Constructor used when encoding the type SIGNED_DATA
	 */
	public Ieee1609Dot2Content(SignedData data) throws IllegalArgumentException{
		super(Ieee1609Dot2ContentChoices.SIGNED_DATA, data);
	}

	/**
	 * Constructor used when encoding the type ENCRYPTED_DATA
	 */
	public Ieee1609Dot2Content(EncryptedData data) throws IllegalArgumentException{
		super(Ieee1609Dot2ContentChoices.ENCRYPTED_DATA, data);
	}

	/**
	 * Constructor used when decoding.
	 */
	public Ieee1609Dot2Content() {
		super(Ieee1609Dot2ContentChoices.class);
	}
		
	/**
	 * Returns the type.
	 */
	public Ieee1609Dot2ContentChoices getType(){
		return (Ieee1609Dot2ContentChoices) choice;
	}


	
}
