package com.multicert.project.v2x.pkimanager.service;

import java.util.List;

import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.Request;
import com.multicert.project.v2x.pkimanager.model.Response;
import com.multicert.project.v2x.pkimanager.model.Vehicle;
import com.multicert.project.v2x.pkimanager.model.VehiclePojo;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.UnknownItsException;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

public interface RAService {

	public void saveRequest(Request request);
	
	public Request getRequest(Long requestId);
	
	/**
	 * Method that verifies if the vehicle is configured within the RA and if the CA is ready to process an ECRequest.
	 * If the both conditions are met, the EcRequest if forwarded to the enrollment CA
	 * Else the vehicle is notified of the problem
	 * @return 
	 */
	public EtsiTs103097Data verifySource(Request request) throws Exception;

	public Vehicle getVehicle(String vehicleName);
	
	public Vehicle saveVehicle(VehiclePojo vehicle) throws BadContentTypeException;

	/**
	 * Method that generates and saves a response to send to the vehicle
	 * @param ecRequest the original database response object
	 * @param encodedResponse the encoded response
	 * @param responseMessage a message to the vehicle 
	 * @return
	 */
	Response genEcResponse(Request ecRequest, byte[] encodedResponse, String responseMessage);
	
	Response getResponse(long responseId);
	
}
