package com.multicert.project.v2x.pkimanager.service;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.Certificate;
import com.multicert.project.v2x.pkimanager.model.Key;
import com.multicert.project.v2x.pkimanager.model.Request;
import com.multicert.project.v2x.pkimanager.model.Response;
import com.multicert.project.v2x.pkimanager.model.Vehicle;
import com.multicert.project.v2x.pkimanager.model.VehiclePojo;
import com.multicert.project.v2x.pkimanager.repository.RequestRepository;
import com.multicert.project.v2x.pkimanager.repository.ResponseRepository;
import com.multicert.project.v2x.pkimanager.repository.VehicleRepository;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.DecryptionException;
import com.multicert.v2x.cryptography.ImcompleteRequestException;
import com.multicert.v2x.cryptography.IncorrectRecipientException;
import com.multicert.v2x.cryptography.InvalidSignatureException;
import com.multicert.v2x.cryptography.UnknownItsException;
import com.multicert.v2x.datastructures.base.EccP256CurvePoint;
import com.multicert.v2x.datastructures.base.PublicVerificationKey;
import com.multicert.v2x.datastructures.base.PublicVerificationKey.PublicVerificationKeyTypes;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

@Service("raService")
public class RAServiceImpl implements RAService {

	@Autowired
	private RequestRepository requestRepository;
	@Autowired
	private VehicleRepository vehicleRepository;
	@Autowired
	private ResponseRepository responseRepository;
	@Autowired
	private CaService caService;
	@Autowired
	private V2XService v2xService;
	


	@Override
	public void saveRequest(Request ecRequest) {
		requestRepository.save(ecRequest);	
		//TODO requests are saved on the BD but also need to be deleted, when vehicle confirms its delivery

	}

	@Override
	public Request getRequest(Long requestId) {
		return requestRepository.findByrequestId(requestId);
	}

	@Override
	public EtsiTs103097Data verifySource(Request ecRequest) throws Exception{
		
		String originName = ecRequest.getRequestOrigin();
		Vehicle origin = getVehicle(originName);
		if(origin == null) 
		{
			throw new UnknownItsException ("Error validating EcRequest: the specified origin is not a known ITS station"); //TODO Send response to car
		}		
		PublicKey canonicalKey = origin.getPublicKey();
		
		String destination = ecRequest.getRequestDestination();
		if(!caService.isReady(destination))
		{
			throw new IncorrectRecipientException ("Error validating EcRequest: Recipient CA does not exist");
		}
		
		byte[] encodedEcRequest = ecRequest.getRequestEncoded();
		
		return caService.validateEcRequest(encodedEcRequest, canonicalKey, destination);
	}
	

	
	@Override
	public Vehicle getVehicle(String vehicleName) {
		return vehicleRepository.findByvehicleId(vehicleName);	
	}
	
	
	@Override
	public Vehicle saveVehicle(VehiclePojo vehicleP) throws BadContentTypeException {
		Vehicle storedVehicle = this.getVehicle(vehicleP.getVehicleId());
		if(storedVehicle != null)
		{
			return storedVehicle;
		}
		
		Vehicle vehicle = pojoToVehicle(vehicleP);
		
		return vehicleRepository.save(vehicle);
	
	}
	
	/**
	 * Help method that transforms a VehiclePojo into the database object Vehicle
	 * @throws BadContentTypeException 
	 */
	private Vehicle pojoToVehicle(VehiclePojo vehicleP) throws BadContentTypeException
	{
		byte[] encodedVerificationKey = vehicleP.getPublicKey();
		
		try {
			PublicVerificationKey decodedVerificationKey = new PublicVerificationKey(encodedVerificationKey);
		
			PublicKey canonicalKey = v2xService.extractPublicKey(decodedVerificationKey);
			String vehicleId = vehicleP.getVehicleId();
			
			return new Vehicle(vehicleId,canonicalKey);
					
		} catch (Exception e) {
			e.printStackTrace();
			throw new BadContentTypeException("Error decoding canonical public key");
		}	
		
	}
	@Override
	public Response genEcResponse(Request ecRequest, byte[]encodedResponse, String resposneMessage)
	{
		Response ecResponse =  new Response(ecRequest.getRequestOrigin(), ecRequest.getRequestDestination(),true, resposneMessage, encodedResponse);
		saveResponse(ecResponse); 
		return ecResponse;
	}

	private void saveResponse(Response ecResponse) {
		responseRepository.save(ecResponse);	
		//TODO responses are saved on the BD but also need to be deleted, when vehicle confirms its delivery
	}
	
	@Override
	public Response getResponse(long responseId) {
		return responseRepository.findByresponseId(responseId);
	}
		
}
