package com.multicert.project.v2x.pkimanager.api.rest;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.multicert.project.v2x.pkimanager.model.ConfigResponse;
import com.multicert.project.v2x.pkimanager.model.Request;
import com.multicert.project.v2x.pkimanager.model.Response;
import com.multicert.project.v2x.pkimanager.model.Vehicle;
import com.multicert.project.v2x.pkimanager.model.VehiclePojo;
import com.multicert.project.v2x.pkimanager.service.RAService;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.DecryptionException;
import com.multicert.v2x.cryptography.IncorrectRecipientException;
import com.multicert.v2x.cryptography.UnknownItsException;

import io.swagger.annotations.ApiOperation;

@RestController
public class RAController {
	  @Autowired
	    private RAService raService;

	    @RequestMapping(value = "/api/conf",
	            method = RequestMethod.POST,
	            consumes = {"application/json"},
	            produces = {"application/json"})
	    @ResponseStatus(HttpStatus.CREATED)
	    @ApiOperation(value = "Configure a vehicle within the RASerice.", notes = "The request should be composed of the vehicle's unique name (9 char long), its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097), and its type. TODO: falar da resposta colocar em bullets....")
	    public ConfigResponse configureVehicle(@RequestBody VehiclePojo vehicle,
	                                 HttpServletRequest request, HttpServletResponse response) throws IOException {
	    	Vehicle createdVehicle;
			try {
				createdVehicle = raService.saveVehicle(vehicle);
			} catch (BadContentTypeException e) {
				e.printStackTrace();
				return raService.genConfigResponse("RAService", vehicle, false, "could not configure the vehicle, the request was badly formed");
			}
			
	        response.setHeader("Location", request.getRequestURL().append("/").append(createdVehicle.getVehicleId()).toString());  
	        return raService.genConfigResponse("RAService", vehicle, true, "The vehicle is sucessfuly configurated");
	    }
	    
	    @RequestMapping(value = "/api/enrollment",
	            method = RequestMethod.POST,
	            consumes = {"application/json"},
	            produces = {"application/json"})
	    @ResponseStatus(HttpStatus.CREATED)
	    @ApiOperation(value = "Request an enrollment credential.", notes = " The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.")
	    public Response requestEnrollmentCert(@RequestBody Request ecRequest,
	                                 HttpServletRequest request, HttpServletResponse response){
	    	
	    	byte[] encodedResponse = null;
	    	
	    	try {
	    		
	    		encodedResponse = raService.verifySource(ecRequest).getEncoded();	   
	    		
	   	
			} catch (Exception e) {
				if(e instanceof IncorrectRecipientException) {
					e.printStackTrace();
			    	return raService.genEcResponse(ecRequest, null, "Wrong recipient, that CA can't receive the request", false);

				}
				if(e instanceof UnknownItsException) {
					e.printStackTrace();
			    	raService.genEcResponse(ecRequest, null, "Vehicle is unknown to the RA, please configure the vehicle first", false);

				}	
				if(e instanceof DecryptionException) {
					e.printStackTrace();
			    	raService.genEcResponse(ecRequest, null, "Could not decryt request", false);

				}
				
				if(e instanceof BadContentTypeException) {
					e.printStackTrace();
			    	raService.genEcResponse(ecRequest, null, "Request is badly formed", false);

				}
				
				e.printStackTrace();
			}
	    	
	    	return raService.genEcResponse(ecRequest, encodedResponse, "Success", true);
	    	
	    }
	    
	    
	
	    
}
