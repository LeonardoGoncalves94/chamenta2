package com.multicert.project.v2x.pkimanager.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.multicert.project.v2x.pkimanager.repository.RegionRepository;


/**
 * This class lists in a hash map the available vehicle's profile
 * A profile is built for a specific type of vehicle (e.g. and ambulance, truck etc..) and contains its enrollment time and region profile
 */
public final class VehicleProfiles {
	
	@Autowired
	private static RegionRepository regionRepository; //the country table to select the region validity of the profiles
	
	public static final Map<String, Profile> vehicleProfiles = new HashMap<String, Profile>();
	
	public static Profile profile1 = new Profile(3, regionRepository.findAll()); //profile with enrollment period for 3 years, and region validity set to all of the available countries
	static {
		vehicleProfiles.put("profile1", profile1);
	}
	
	static public class Profile
	{	
		
		private int enrollmentPeriod;
		private List <Region> countries; 
		
		/**
		 * Main constructor to build a vehicle profile
		 * @param enrollmentPeriod, the enrollment period of this vehicle profile
		 * @param countries, the region validity of this vehicle profile
		 */
		public Profile(int enrollmentPeriod, List <Region> countries)
		{
			this.enrollmentPeriod = enrollmentPeriod;
			this.countries = countries;
			
		}
		
		public int getEnrollmentPeriod()
		{
			return this.enrollmentPeriod;
		}
		
		public List <Region> getCountries()
		{
			return this.countries;
		}
		
	}
}
