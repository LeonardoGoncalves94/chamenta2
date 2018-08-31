package com.multicert.v2x.datastructures.message.secureddata;

import com.multicert.v2x.asn1.coer.COERSequence;
import com.multicert.v2x.datastructures.base.*;


import java.io.IOException;

public class HeaderInfo extends COERSequence
{

	private static final int SEQUENCE_SIZE = 7;
	
	private static final int PSID = 0;
	private static final int GENERATION_TIME = 1;
	private static final int EXPIRY_TIME = 2;
	private static final int GENERATION_LOCATION = 3;
	private static final int P2PCD_LEARNING_REQUEST = 4; //always ABSENT in ETSI TS 103 097
	private static final int MISSING_CRL_IDENTIFIER = 5; //always ABSENT in ETSI TS 103 097
	private static final int ENCRYPTION_KEY = 6;

	/**
	 * Constructor used when encoding
	 */
	public HeaderInfo(Psid psid, Time64 generationTime, Time64 expiryTime, ThreeDLocation generationLocation,EncryptionKey encryptionKey) throws IOException
	{
		super(SEQUENCE_SIZE);
		createSequence();
		setComponentValue(PSID, psid);
		setComponentValue(GENERATION_TIME, generationTime);
		setComponentValue(EXPIRY_TIME, expiryTime);
		setComponentValue(GENERATION_LOCATION, generationLocation);
		setComponentValue(P2PCD_LEARNING_REQUEST, null); //ABSENT
		setComponentValue(MISSING_CRL_IDENTIFIER, null); //ABSENT
		setComponentValue(ENCRYPTION_KEY, encryptionKey);
	}

	/**
	 * Constructor used when decoding
	 */
	public HeaderInfo()
    {
		super(SEQUENCE_SIZE);
		createSequence();
	}

	/**
	 * 
	 * @return psid, required
	 */
	public Psid getPsid()
    {
		return (Psid) getComponentValue(PSID);
	}
	
	/**
	 * 
	 * @return generationTime, optional, null if not set
	 */
	public Time64 getGenerationTime()
    {
		return (Time64) getComponentValue(GENERATION_TIME);
	}
	
	/**
	 * 
	 * @return expiryTime, optional, null if not set
	 */
	public Time64 getExpiryTime()
    {
		return (Time64) getComponentValue(EXPIRY_TIME);
	}
	
	/**
	 * 
	 * @return generationLocation, optional, null if not set
	 */
	public ThreeDLocation getGenerationLocation()
    {
		return (ThreeDLocation) getComponentValue(GENERATION_LOCATION);
	}

	
	/**
	 * 
	 * @return encryptionKey, optional, null if not set
	 */
	public EncryptionKey getEncryptionKey()
    {
		return (EncryptionKey) getComponentValue(ENCRYPTION_KEY);
	}
	
	private void createSequence()
    {
		addComponent(PSID, false, new Psid(), null);
		addComponent(GENERATION_TIME, true, new Time64(), null);
		addComponent(EXPIRY_TIME, true, new Time64(), null);
		addComponent(GENERATION_LOCATION, true, new ThreeDLocation(), null);
		addComponent(P2PCD_LEARNING_REQUEST, true, new HashedId3(), null);
		addComponent(MISSING_CRL_IDENTIFIER, true, new MissingCrlIdentifier(), null);
		addComponent(ENCRYPTION_KEY, true, new EncryptionKey(), null);
	}

	@Override
	public String toString() {
		String retval = "HeaderInfo [\n"+
				"  psid=" + getPsid().toString().replace("Psid ", "") +  ",\n"+
				(getGenerationTime() != null ? "  generationTime=" + getGenerationTime().toString().replace("Time64 ", "")   +  ",\n" : "") +
				(getExpiryTime() != null ? "  expiryTime=" + getExpiryTime().toString().replace("Time64 ", "")   +  ",\n" : "") +
				(getGenerationLocation() != null ? "  generationLocation=" + getGenerationLocation().toString().replace("ThreeDLocation ", "")   +  ",\n" : "")+
				(getEncryptionKey() != null ? "  encryptionKey=" + getEncryptionKey().toString().replace("EncryptionKey ", "")   +  "\n" : "")+
				"]";
		if(retval.endsWith(",\n]")){
			retval = retval.substring(0, retval.length()-3) + "\n]";
		}
		return retval;
	}

}
