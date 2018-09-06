/*
 * RA Service
 * The RAservice is responsible for handling the request for enrollment and authorization certificates 
 *
 * OpenAPI spec version: 1.0
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.multicert.project.v2x.client.api;

import com.multicert.project.v2x.client.invoker.ApiException;
import com.multicert.project.v2x.client.model.Request;
import com.multicert.project.v2x.client.model.Response;
import com.multicert.project.v2x.client.model.VehiclePojo;
import org.junit.Test;
import org.junit.Ignore;


/**
 * API tests for RaControllerApi
 */
@Ignore
public class RaControllerApiTest {

    private final RaControllerApi api = new RaControllerApi();

    
    /**
     * Configure a vehicle within the RASerice.
     *
     * The request should be composed of the vehicle&#39;s unique name and its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097).
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void configureVehicleUsingPOSTTest() throws ApiException {
        VehiclePojo vehicle = null;
        String response = api.configureVehicleUsingPOST(vehicle);

        // TODO: test validations
    }
    
    /**
     * Request an enrollment credential.
     *
     *  The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void requestEnrollmentCertUsingPOSTTest() throws ApiException {
        Request ecRequest = null;
        Response response = api.requestEnrollmentCertUsingPOST(ecRequest);

        // TODO: test validations
    }
    
}