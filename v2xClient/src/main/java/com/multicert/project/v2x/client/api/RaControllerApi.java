package com.multicert.project.v2x.client.api;

import com.multicert.project.v2x.client.invoker.ApiException;
import com.multicert.project.v2x.client.invoker.ApiClient;
import com.multicert.project.v2x.client.invoker.Configuration;
import com.multicert.project.v2x.client.invoker.Pair;

import javax.ws.rs.core.GenericType;

import com.multicert.project.v2x.client.model.Request;
import com.multicert.project.v2x.client.model.Response;
import com.multicert.project.v2x.client.model.VehiclePojo;


@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2018-09-05T11:42:30.831+01:00")
public class RaControllerApi {
  private ApiClient apiClient;

  public RaControllerApi() {
    this(Configuration.getDefaultApiClient());
  }

  public RaControllerApi(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  public ApiClient getApiClient() {
    return apiClient;
  }

  public void setApiClient(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Configure a vehicle within the RASerice.
   * The request should be composed of the vehicle's unique name and its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097).
   * @param vehicle vehicle (required)
   * @return String
   * @throws ApiException if fails to make API call
   */
  public String configureVehicleUsingPOST(VehiclePojo vehicle) throws ApiException {
    Object localVarPostBody = vehicle;
    
    // verify the required parameter 'vehicle' is set
    if (vehicle == null) {
      throw new ApiException(400, "Missing the required parameter 'vehicle' when calling configureVehicleUsingPOST");
    }
    
    // create path and map variables
    String localVarPath = "/api/conf";

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();


    
    
    final String[] localVarAccepts = {
      "application/json"
    };
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {
      "application/json"
    };
    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {  };

    GenericType<String> localVarReturnType = new GenericType<String>() {};
    return apiClient.invokeAPI(localVarPath, "POST", localVarQueryParams, localVarPostBody, localVarHeaderParams, localVarFormParams, localVarAccept, localVarContentType, localVarAuthNames, localVarReturnType);
      }
  /**
   * Request an enrollment credential.
   *  The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.
   * @param ecRequest ecRequest (required)
   * @return Response
   * @throws ApiException if fails to make API call
   */
  public Response requestEnrollmentCertUsingPOST(Request ecRequest) throws ApiException {
    Object localVarPostBody = ecRequest;
    
    // verify the required parameter 'ecRequest' is set
    if (ecRequest == null) {
      throw new ApiException(400, "Missing the required parameter 'ecRequest' when calling requestEnrollmentCertUsingPOST");
    }
    
    // create path and map variables
    String localVarPath = "/api/enrollment";

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();


    
    
    final String[] localVarAccepts = {
      "application/json"
    };
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {
      "application/json"
    };
    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {  };

    GenericType<Response> localVarReturnType = new GenericType<Response>() {};
    return apiClient.invokeAPI(localVarPath, "POST", localVarQueryParams, localVarPostBody, localVarHeaderParams, localVarFormParams, localVarAccept, localVarContentType, localVarAuthNames, localVarReturnType);
      }
}
