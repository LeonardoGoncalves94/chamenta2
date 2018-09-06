package com.multicert.project.v2x.client;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;


import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.datastructures.base.Signature;

public class VehicleGenerator {
	
	private Map<String, Vehicle> vehicles = new HashMap<String, Vehicle>();
	private AlgorithmType vehicleAlg = Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;
	private int numberOfVehicles;
	
	/**
	 * Constructor used for generating vehicles with the default public key algorithm
	 * @param numberOfVehicles number of vehicles that will be generated
	 */
	public VehicleGenerator(int numberOfVehicles) throws Exception
	{
		this.numberOfVehicles = numberOfVehicles;
		
	}
	
	/**
	 * Constructor used for generating vehicles with a specific public key algorithm
	 * @param numberOfVehicles  number of vehicles that will be generated
	 * @param vehicleAlg the algorithm to be used for generating each vehicle's keys (use an item of Signature.SignatureTypes)
	 */
	public VehicleGenerator(int numberOfVehicles, AlgorithmType vehicleAlg) throws Exception
	{
		this.numberOfVehicles = numberOfVehicles;
		this.vehicleAlg = vehicleAlg;
		
	}
	
	public void init() throws Exception
	{
		V2X v2x = new V2XImpl();
		RandomStringGenerator gen = new RandomStringGenerator(9); 
		
		for(int i = 0; i < numberOfVehicles; i ++) 
		{
			String itsId = gen.nextString();
			KeyPair itscanonicalPair = v2x.genKeyPair(vehicleAlg);
			
			vehicles.put(itsId, new Vehicle(itsId,itscanonicalPair));
		}
	}

	public Map<String, Vehicle> getVehicles() {
		return vehicles;
	}
	


}
