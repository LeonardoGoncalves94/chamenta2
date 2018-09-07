package com.multicert.project.v2x.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.bouncycastle.util.encoders.Hex;

import com.multicert.project.v2x.client.api.RaControllerApi;
import com.multicert.project.v2x.client.model.VehiclePojo;
import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;

public class Vehicle {
	
	private String itsId;
	KeyPair canonicalPair = null;
	AlgorithmType canonicalAlg = null;
	V2X v2x = null;
	RaControllerApi raApi = null;
	
	public Vehicle(String itsId, KeyPair canonicalPair, AlgorithmType canonicalAlg, V2X v2x)
	{
		this.itsId = itsId;
		this.canonicalPair = canonicalPair;
		this.canonicalAlg = canonicalAlg;
		this.v2x = v2x;
		raApi = new RaControllerApi();
	}
	
	public void configureVehicle() throws IllegalArgumentException, InvalidKeySpecException, IOException
	{
		PublicVerificationKey PubVerKey = v2x.buildVerificationKey(canonicalPair.getPublic(),canonicalAlg);
		
		VehiclePojo vehicle = new VehiclePojo();
		vehicle.setPublicKey(Hex.toHexString(PubVerKey.getEncoded())); // encoded public verification key to string
		vehicle.setVehicleId(itsId);
		raApi.configureVehicleUsingPOST(vehicle);
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
	                        "  canonicalAlgorithm=" + canonicalAlg.toString() + "\n" +	
	                        "]";
	}
	
}
