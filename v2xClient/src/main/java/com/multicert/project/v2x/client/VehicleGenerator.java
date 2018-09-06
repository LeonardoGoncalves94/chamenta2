package com.multicert.project.v2x.client;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

public class VehicleGenerator {

	
	private static final Map<String, Vehicle> vehicles = new HashMap<String, Vehicle>();
	
	public VehicleGenerator(int numberOfVehicles)
	{
		for(int i = 0; i < numberOfVehicles; i ++) 
		{
			
		}
	}
	
	private String genUniqueName()
	{
		return "uniq";
	}
	
	private KeyPair genKeyPair()
	{
		return null;
	}

}
