package com.multicert.project.v2x.pkimanager.api.rest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.multicert.project.v2x.pkimanager.model.Request;
import com.multicert.project.v2x.pkimanager.model.Vehicle;
import com.multicert.project.v2x.pkimanager.model.VehiclePojo;
import com.multicert.project.v2x.pkimanager.service.RAService;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.DecryptionException;
import com.multicert.v2x.cryptography.ImcompleteRequestException;
import com.multicert.v2x.cryptography.IncorrectRecipientException;
import com.multicert.v2x.cryptography.InvalidSignatureException;
import com.multicert.v2x.cryptography.UnknownItsException;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
public class RAController {
	  @Autowired
	    private RAService raService;

	    @RequestMapping(value = "/conf",
	            method = RequestMethod.POST,
	            consumes = {"application/json", "application/xml"},
	            produces = {"application/json", "application/xml"})
	    @ResponseStatus(HttpStatus.CREATED)
	    @ApiOperation(value = "Configure a vehicle within the RASerice.", notes = "The request should be composed of the vehicle's unique name and its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097).")
	    public String configureVehicle(@RequestBody VehiclePojo vehicle,
	                                 HttpServletRequest request, HttpServletResponse response) {
	    	Vehicle createdVehicle;
			try {
				createdVehicle = raService.saveVehicle(vehicle);
			} catch (BadContentTypeException e) {
				e.printStackTrace();
				return "could not configure the vehicle, the request was badly formed";
			}
			
	        response.setHeader("Location", request.getRequestURL().append("/").append(createdVehicle.getVehicleId()).toString());  
	        return "The vehicle is sucessfuly configurated";
	    }
	    
	    @RequestMapping(value = "/enrollment",
	            method = RequestMethod.POST,
	            consumes = {"application/json", "application/xml"},
	            produces = {"application/json", "application/xml"})
	    @ResponseStatus(HttpStatus.CREATED)
	    @ApiOperation(value = "Request an enrollment credential.", notes = " The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.")
	    public void requestEnrollmentCert(@RequestBody Request ecRequest,
	                                 HttpServletRequest request, HttpServletResponse response){
	    	try {
	    		
	    		raService.verifySource(ecRequest);
	   	
			} catch (Exception e) {
				if(e instanceof IncorrectRecipientException) {
					// TODO Notify vehicle that sent to the wrong CA
					e.printStackTrace();
				}
				if(e instanceof UnknownItsException) {
					// TODO Notify vehicle that it is not configured in the RA
					e.printStackTrace();
				}		
			}
	    }
	    
}
