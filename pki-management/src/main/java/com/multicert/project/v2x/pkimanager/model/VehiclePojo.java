package com.multicert.project.v2x.pkimanager.model;

/**
 * Simplification of the Database object Vehicle, this class contains:
 * 
 * The vehicleId which represents the vehicle's unique name.
 * The canonicalPublicKey representing the vehicle's encoded public key. Such public key must be an encoded PublicVerificationKey structure from EtsiTs103 097
 *
 */
public class VehiclePojo {
	
	public VehiclePojo() {
	
	}
	
	private String vehicleId;
	
	private String canonicalPublicKey;

	public String getVehicleId() {
		return vehicleId;
	}

	public void setVehicleId(String vehicleId) {
		this.vehicleId = vehicleId;
	}

	public String getPublicKey() {
		return canonicalPublicKey;
	}

	public void setPublicKey(String publicKey) {
		this.canonicalPublicKey = publicKey;
	}
	
}
