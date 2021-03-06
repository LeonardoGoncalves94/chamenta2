package com.multicert.project.v2x.pkimanager.service;

import java.io.IOException;
import java.util.List;

import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.ConfigResponse;
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
	 * Method that generates and saves a response to vehicle enrollment
	 * @param ecRequest the original enrollment request, stored at in the database
	 * @param encodedResponse the encoded response
	 * @param responseMessage a message to the vehicle 
	 * @param isSuccess if the enrollment of the vehicle was successful or not
	 * @return the enrollment certificate or an error code
	 */
	Response genEcResponse(Request ecRequest, byte[] encodedResponse, String responseMessage, Boolean isSuccess);
	
	Response getResponse(long responseId);
	/**
	 * Method that generates and saves a response to vehicle configuration
	 * @para, the name of the RA that will respond to the vehicle
	 * @param vehicle the destination vehicle
	 * @param isSuccess if the configuration of the vehicle was successful or not
	 * @param resposneMessage a response message
	 * @return returns the trusted Ca certificates or error code
	 * @throws IOException 
	 */
	ConfigResponse genConfigResponse(String RAname, VehiclePojo vehicleP, boolean isSuccess, String resposneMessage)
			throws IOException;
	
}
