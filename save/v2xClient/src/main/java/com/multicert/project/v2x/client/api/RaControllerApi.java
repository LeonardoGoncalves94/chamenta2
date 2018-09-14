package com.multicert.project.v2x.client.api;

import com.multicert.project.v2x.client.invoker.ApiClient;

import com.multicert.project.v2x.client.model.Request;
import com.multicert.project.v2x.client.model.Response;
import com.multicert.project.v2x.client.model.VehiclePojo;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2018-09-07T17:25:28.225+01:00")
@Component("com.multicert.project.v2x.client.api.RaControllerApi")
public class RaControllerApi {
    private ApiClient apiClient;

    public RaControllerApi() {
        this(new ApiClient());
    }

    @Autowired
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
     * The request should be composed of the vehicle&#39;s unique name (9 char long) and its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097).
     * <p><b>201</b> - Created
     * <p><b>401</b> - Unauthorized
     * <p><b>403</b> - Forbidden
     * <p><b>404</b> - Not Found
     * @param vehicle vehicle
     * @return String
     * @throws RestClientException if an error occurs while attempting to invoke the API
     */
    public String configureVehicleUsingPOST(VehiclePojo vehicle) throws RestClientException {
        Object postBody = vehicle;
        
        // verify the required parameter 'vehicle' is set
        if (vehicle == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Missing the required parameter 'vehicle' when calling configureVehicleUsingPOST");
        }
        
        String path = UriComponentsBuilder.fromPath("/api/conf").build().toUriString();
        
        final MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<String, String>();
        final HttpHeaders headerParams = new HttpHeaders();
        final MultiValueMap<String, Object> formParams = new LinkedMultiValueMap<String, Object>();

        final String[] accepts = { 
            "application/json"
        };
        final List<MediaType> accept = apiClient.selectHeaderAccept(accepts);
        final String[] contentTypes = { 
            "application/json"
        };
        final MediaType contentType = apiClient.selectHeaderContentType(contentTypes);

        String[] authNames = new String[] {  };

        ParameterizedTypeReference<String> returnType = new ParameterizedTypeReference<String>() {};
        return apiClient.invokeAPI(path, HttpMethod.POST, queryParams, postBody, headerParams, formParams, accept, contentType, authNames, returnType);
    }
    /**
     * Request an enrollment credential.
     *  The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.
     * <p><b>201</b> - Created
     * <p><b>401</b> - Unauthorized
     * <p><b>403</b> - Forbidden
     * <p><b>404</b> - Not Found
     * @param ecRequest ecRequest
     * @return Response
     * @throws RestClientException if an error occurs while attempting to invoke the API
     */
    public Response requestEnrollmentCertUsingPOST(Request ecRequest) throws RestClientException {
        Object postBody = ecRequest;
        
        // verify the required parameter 'ecRequest' is set
        if (ecRequest == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Missing the required parameter 'ecRequest' when calling requestEnrollmentCertUsingPOST");
        }
        
        String path = UriComponentsBuilder.fromPath("/api/enrollment").build().toUriString();
        
        final MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<String, String>();
        final HttpHeaders headerParams = new HttpHeaders();
        final MultiValueMap<String, Object> formParams = new LinkedMultiValueMap<String, Object>();

        final String[] accepts = { 
            "application/json"
        };
        final List<MediaType> accept = apiClient.selectHeaderAccept(accepts);
        final String[] contentTypes = { 
            "application/json"
        };
        final MediaType contentType = apiClient.selectHeaderContentType(contentTypes);

        String[] authNames = new String[] {  };

        ParameterizedTypeReference<Response> returnType = new ParameterizedTypeReference<Response>() {};
        return apiClient.invokeAPI(path, HttpMethod.POST, queryParams, postBody, headerParams, formParams, accept, contentType, authNames, returnType);
    }
}
