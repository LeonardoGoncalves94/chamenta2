package com.multicert.v2x.datastructures.message.encrypteddata;


import com.multicert.v2x.datastructures.base.HashedId8;

/**
 * This classis used to indicate a pre shared symmetric key that may be used to decrypt a SymmetricCiphertext.
 *
 */
public class PreSharedKeyRecipientInfo extends HashedId8
{
    /**
     * Constructor used when encoding
     */
    public PreSharedKeyRecipientInfo(byte[] recipientInfo)
    {
        super(recipientInfo);
    }
	
	/**
	 * Constructor used when decoding
	 */
	public PreSharedKeyRecipientInfo(){
	}

}
