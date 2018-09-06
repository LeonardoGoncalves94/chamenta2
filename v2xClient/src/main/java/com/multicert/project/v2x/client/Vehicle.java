package com.multicert.project.v2x.client;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

public class Vehicle {
	
	private String itsId;
	KeyPair canonicalPair = null;
	
	public Vehicle(String itsId, KeyPair canonicalPair)
	{
		this.itsId = itsId;
		this.canonicalPair = canonicalPair;
	}
	
	public void configureVehicle()
	{
		//TODO call the RA /api/conf end point
	}
	
	public void enrollVehicle()
	{
		
	}
	
	public void authorizeVehicle()
	{
		
	}
	
	public void sendCAM()
	{
		
	}
	
	public void sendDEMN()
	{
		
	}
	
	public String toString()
	{
		PublicKey pubKey = canonicalPair.getPublic();
		 return
	                "vehicle [\n" +
	                        "  id=" + itsId + "\n" +
	                        "  canonicalPubKey=" + Base64.getEncoder().encodeToString(pubKey.getEncoded()) + "\n" +	             
	                        "]";
	}
	
}
