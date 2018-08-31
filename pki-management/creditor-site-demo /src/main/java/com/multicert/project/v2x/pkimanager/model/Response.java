package com.multicert.project.v2x.pkimanager.model;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "response")
public class Response {
	
	public Response(String responseOrigin, String responseDestination,Boolean responseType, byte[] responseEncoded) {
		super();
		this.responseOrigin = responseOrigin;
		this.responseDestination = responseDestination;
		this.responseType = responseType;
		this.responseEncoded = responseEncoded;

	}
	
	public Response() {
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "res_id")
	private Long responseId;
	
	@Column(name = "res_origin")
	@NotEmpty(message = "*Please provide a valid origin")
	private String responseOrigin;
	
	@Column(name = "res_destination")
	@NotEmpty(message = "*Please provide a valid destination")
	private String responseDestination;
	
	@Column(name = "res_type")
	@Length(min = 3, max = 30)
	private Boolean responseType;	
	
	@Column(name = "req_encoded")
	@NotEmpty(message = "*Please provide encoded request")
	private byte[] responseEncoded;

	public Long getRequestId() {
		return responseId;
	}

	public void setRequestId(Long requestId) {
		this.responseId = requestId;
	}

	public Boolean getRequestType() {
		return responseType;
	}

	public void setRequestType(Boolean requestType) {
		this.responseType = requestType;
	}

	public byte[] getRequestEncoded() {
		return responseEncoded;
	}

	public void setRequestEncoded(byte[] requestEncoded) {
		this.responseEncoded = requestEncoded;
	}

	public String getRequestOrigin() {
		return responseOrigin;
	}

	public void setRequestOrigin(String requestOrigin) {
		this.responseOrigin = requestOrigin;
	}

	public String getRequestDestination() {
		return responseDestination;
	}

	public void setRequestDestination(String requestDestination) {
		this.responseDestination = requestDestination;
	}
	



}
