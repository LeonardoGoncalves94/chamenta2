package com.multicert.project.v2x.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import com.multicert.project.v2x.client.api.RaControllerApi;
import com.multicert.project.v2x.client.model.ConfigResponse;
import com.multicert.project.v2x.client.model.Request;
import com.multicert.project.v2x.client.model.Response;
import com.multicert.project.v2x.client.model.VehiclePojo;
import com.multicert.v2x.cryptography.AlgorithmType;
import com.multicert.v2x.datastructures.base.HashedId8;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.datastructures.certificate.SequenceOfCertificate;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

public class Vehicle {
	
	private String itsId;
	private KeyPair canonicalPair = null;
	KeyPair verificationKeys = null;
	private AlgorithmType vehicleAlg = null; //algorithm that will be used for this vehicle's cryptographic operations (signature and encryption)
	private V2X v2x = null;
	private RaControllerApi raApi = null;
	
	EtsiTs103097Certificate trustAnchor; //the certificate of the root CA
	private Map<HashedId8, EtsiTs103097Certificate> trustStore = new HashMap<HashedId8, EtsiTs103097Certificate>(); //The collection of trusted AA certificates
	EtsiTs103097Certificate eaCert; //the certificate of the EA that will enroll this vehicle
	EtsiTs103097Certificate aaCert; //the certificate of the AA that will authorize this vehicle
	
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
		ConfigResponse response = raApi.configureVehicleUsingPOST(vehicle);
		
		
		if(response.getIsSuccess())
		{
			trustAnchor = new EtsiTs103097Certificate(decodeHex(response.getTrustAnchor()));
			eaCert = new EtsiTs103097Certificate(decodeHex(response.getEaCert()));
			aaCert = new EtsiTs103097Certificate(decodeHex(response.getAaCert()));
						
			SequenceOfCertificate certSequence = new SequenceOfCertificate(decodeHex(response.getTrustedAA())); // get the sequence of trusted AA certificates
			EtsiTs103097Certificate[] certArray = certSequence.getCerts();
			trustStore = v2x.genTrustStore(certArray); // store the AA certificates in a trustStore
			
			//System.out.println("Trust Anchor"+ trustAnchor.toString());
			
			//System.out.println("EA cert"+ eaCert.toString());
			
			//System.out.println("AA cert"+ aaCert.toString());

			
			for(Map.Entry<HashedId8, EtsiTs103097Certificate> ent : trustStore.entrySet())
			{
				//System.out.println("Trusted AA"+ent.getValue().toString());
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
		ConfigResponse response = raApi.configureVehicleUsingPOST(vehicle);
		
		

		if(response.getIsSuccess())
		{
			trustAnchor = new EtsiTs103097Certificate(decodeHex(response.getTrustAnchor()));
			eaCert = new EtsiTs103097Certificate(decodeHex(response.getAaCert()));
			aaCert = new EtsiTs103097Certificate(decodeHex(response.getAaCert()));
						
			SequenceOfCertificate certSequence = new SequenceOfCertificate(decodeHex(response.getTrustedAA())); // get the sequence of trusted AA certificates
			EtsiTs103097Certificate[] certArray = certSequence.getCerts();
			trustStore = v2x.genTrustStore(certArray); // store the AA certificates in a trustStore
			
			//System.out.println("Trust Anchor"+ trustAnchor.toString());
			
			//System.out.println("EA cert"+ eaCert.toString());
			
			//System.out.println("AA cert"+ aaCert.toString());

			
			for(Map.Entry<HashedId8, EtsiTs103097Certificate> ent : trustStore.entrySet())
			{
				//System.out.println("Trusted AA"+ent.getValue().toString());
			}
		}
		else
		{
			System.out.println(response.getResponseMessage());
		}
	}
	
	public void enrollVehicle() throws GeneralSecurityException, Exception
	{
		verificationKeys = v2x.genKeyPair(vehicleAlg); //generate a new verification key pair
		EtsiTs103097Data etsiRequest = v2x.genEcRequest(itsId, canonicalPair, verificationKeys,vehicleAlg, 1, 2, eaCert); //dummy assurance and confidence
		
		Request request = new Request();
		request.setRequestDestination(eaCert.getName()); 
		request.setRequestOrigin(itsId);
		request.setRequestType(true);//Set to true for enrollment request and false for authorization
		request.setRequestEncoded(encodeHex(etsiRequest.getEncoded()));
	
		
		
		Response response = raApi.requestEnrollmentCertUsingPOST(request);
		
		System.out.println(response.getResponseMessage());

		

		
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
