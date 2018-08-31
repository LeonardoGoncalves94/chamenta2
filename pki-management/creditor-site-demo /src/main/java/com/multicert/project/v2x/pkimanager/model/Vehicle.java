package com.multicert.project.v2x.pkimanager.model;

import java.security.PublicKey;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.Entity;

@Entity
@Table(name = "vehicle")
public class Vehicle {
	
	public Vehicle(String vehicleId, PublicKey publicKey) {
		super();
		this.vehicleId = vehicleId;
		this.canonicalPublicKey = publicKey;
	}
	
	public Vehicle() {
		
	}

	@Id
	@Column(name="vehicle_id")
	@Length(min = 5, max = 20)
	@NotEmpty
	private String vehicleId;
	
	@Column(name="pubKey")
	@NotEmpty(message = "please provide a public key")
	private PublicKey canonicalPublicKey;

	public String getVehicleId() {
		return vehicleId;
	}

	public void setVehicleId(String vehicleId) {
		this.vehicleId = vehicleId;
	}

	public PublicKey getPublicKey() {
		return canonicalPublicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.canonicalPublicKey = publicKey;
	}
	
}
