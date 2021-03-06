# RaControllerApi

All URIs are relative to *https://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**configureVehicleUsingPOST**](RaControllerApi.md#configureVehicleUsingPOST) | **POST** /api/conf | Configure a vehicle within the RASerice.
[**requestEnrollmentCertUsingPOST**](RaControllerApi.md#requestEnrollmentCertUsingPOST) | **POST** /api/enrollment | Request an enrollment credential.


<a name="configureVehicleUsingPOST"></a>
# **configureVehicleUsingPOST**
> String configureVehicleUsingPOST(vehicle)

Configure a vehicle within the RASerice.

The request should be composed of the vehicle&#39;s unique name (9 char long) and its canonical public key (encoded PublicVerificationKey structure as defined in EtsiTs 103 097).

### Example
```java
// Import classes:
//import com.multicert.project.v2x.client.invoker.ApiException;
//import com.multicert.project.v2x.client.api.RaControllerApi;


RaControllerApi apiInstance = new RaControllerApi();
VehiclePojo vehicle = new VehiclePojo(); // VehiclePojo | vehicle
try {
    String result = apiInstance.configureVehicleUsingPOST(vehicle);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling RaControllerApi#configureVehicleUsingPOST");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vehicle** | [**VehiclePojo**](VehiclePojo.md)| vehicle |

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="requestEnrollmentCertUsingPOST"></a>
# **requestEnrollmentCertUsingPOST**
> Response requestEnrollmentCertUsingPOST(ecRequest)

Request an enrollment credential.

 The request should contain an encoded enrollmentRequest as defined in EtsiTs 102 041.

### Example
```java
// Import classes:
//import com.multicert.project.v2x.client.invoker.ApiException;
//import com.multicert.project.v2x.client.api.RaControllerApi;


RaControllerApi apiInstance = new RaControllerApi();
Request ecRequest = new Request(); // Request | ecRequest
try {
    Response result = apiInstance.requestEnrollmentCertUsingPOST(ecRequest);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling RaControllerApi#requestEnrollmentCertUsingPOST");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ecRequest** | [**Request**](Request.md)| ecRequest |

### Return type

[**Response**](Response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

