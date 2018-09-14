package com.multicert.project.v2x.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import com.multicert.project.v2x.client.api.RaControllerApi;
import com.multicert.project.v2x.client.model.Response;
import com.multicert.project.v2x.client.model.VehiclePojo;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.datastructures.base.HashedId8;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.datastructures.certificate.SequenceOfCertificate;

public class Vehicle {
	
	private String itsId;
	private KeyPair canonicalPair = null;
	private AlgorithmType vehicleAlg = null; //algorithm that will be used for this vehicle's cryptographic operations (signature and encryption)
	private V2X v2x = null;
	private RaControllerApi raApi = null;
	private Map<HashedId8, EtsiTs103097Certificate> trustStore = new HashMap<HashedId8, EtsiTs103097Certificate>();
	
	public Vehicle(String itsId, KeyPair canonicalPair, AlgorithmType vehicleAlg, V2X v2x)
	{
		this.itsId = itsId;
		this.canonicalPair = canonicalPair;
		this.vehicleAlg = vehicleAlg;
		this.v2x = v2x;
		raApi = new RaControllerApi();
	}
	/**
	 * This method creates a request for vehicle configuration to the RAService
	 * @throws IllegalArgumentException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 */
	public void configureVehicle() throws IllegalArgumentException, InvalidKeySpecException, IOException, NoSuchAlgorithmException
	{
		PublicVerificationKey PubVerKey = v2x.buildVerificationKey(canonicalPair.getPublic(),vehicleAlg);
		
		VehiclePojo vehicle = new VehiclePojo();
		vehicle.setPublicKey(Hex.toHexString(PubVerKey.getEncoded())); // encoded public verification key to string
		vehicle.setVehicleId(itsId);
		Response response = raApi.configureVehicleUsingPOST(vehicle);
		
		
		if(response.getIsSuccess())
		{
			SequenceOfCertificate certSequence = new SequenceOfCertificate(decodeHex(response.getResponseEncoded())); // get the sequence of certificates
			EtsiTs103097Certificate[] certArray = certSequence.getCerts();
			trustStore = v2x.genTrustStore(certArray); // store the CA certificates in a trustStore
			
			for(Map.Entry<HashedId8, EtsiTs103097Certificate> ent : trustStore.entrySet())
			{
				System.out.println(ent.getKey().toString());
				System.out.println(ent.getValue().toString());
			}
		}
		else
		{
			System.out.println(response.getResponseMessage());
		}
		
	}
	
	/**
	 * Test method creates a bad formatted request for vehicle configuration to the RAService
	 */
	public void wrongConfigureVehicle() throws IllegalArgumentException, InvalidKeySpecException, IOException, NoSuchAlgorithmException
	{

		
		VehiclePojo vehicle = new VehiclePojo();
		vehicle.setPublicKey(Hex.toHexString(new byte[] {(byte) 1313123})); // badly encoded canonical key
		vehicle.setVehicleId(itsId);
		Response response = raApi.configureVehicleUsingPOST(vehicle);
		
		
		if(response.getIsSuccess())
		{
			SequenceOfCertificate certSequence = new SequenceOfCertificate(decodeHex(response.getResponseEncoded())); // get the sequence of certificates
			EtsiTs103097Certificate[] certArray = certSequence.getCerts();
			trustStore = v2x.genTrustStore(certArray); // store the CA certificates in a trustStore
		}
		else
		{
			System.out.println(response.getResponseMessage());
		}
		
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
	
	/**
	 * Help method that encodes bytes into string
	 * @param bytes
	 * @return
	 */
	private String encodeHex(byte[] bytes)
	{
		return Hex.toHexString(bytes);
	}
	
	/**
	 * Help method that encodes bytes into string
	 * @param bytes
	 * @return
	 */
	private byte[] decodeHex(String string)
	{
		return Hex.decode(string);
	}
	
	public String toString()
	{
		PublicKey pubKey = canonicalPair.getPublic();
		 return
	                "vehicle [\n" +
	                        "  id=" + itsId + "\n" +
	                        "  canonicalPubKey=" + Base64.getEncoder().encodeToString(pubKey.getEncoded()) + "\n" +
	                        "  canonicalAlgorithm=" + vehicleAlg.toString() + "\n" +	
	                        "]";
	}
	
}
