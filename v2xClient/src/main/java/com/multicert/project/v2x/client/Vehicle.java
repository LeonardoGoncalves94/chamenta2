package com.multicert.project.v2x.client;

import java.security.KeyPair;

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
	
}
