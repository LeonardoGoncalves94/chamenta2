package com.multicert.project.v2x.client;

import java.util.Map.Entry;

public class Main {
	
	public static V2X v2x; //an interface to the v2x package
	
	public static void main(String[] args) throws Exception {
		init();
		VehicleGenerator vg = new VehicleGenerator(1, v2x);
		vg.init();
		
		for (Entry<String, Vehicle> entry : vg.getVehicles().entrySet())
		{
			entry.getValue().configureVehicle();
		}
		
	}
	
	public static void init() throws Exception 
	{
		v2x = new V2XImpl();
	}
	

}
