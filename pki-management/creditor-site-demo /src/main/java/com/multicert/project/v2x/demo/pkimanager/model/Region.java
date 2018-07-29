package com.multicert.project.v2x.demo.pkimanager.model;



import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "country")
public class Region {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "region_id")
	private Long regionId;
	
	@Column(name = "region_name")
	@Length(min = 2, max = 30)
	@NotEmpty(message = "*Please provide an Country name")
	private String regionName;
	
	@Column(name = "region_number")
	@NotEmpty(message = "*Please provide an Country number")
	private Long regionNumber;

	public Long getRegionId() {
		return regionId;
	}

	public void setRegionId(Long regionId) {
		this.regionId = regionId;
	}

	public String getRegionName() {
		return regionName;
	}

	public void setRegionName(String regionName) {
		this.regionName = regionName;
	}

	public Long getRegionNumber() {
		return regionNumber;
	}

	public void setRegionNumber(Long regionNumber) {
		this.regionNumber = regionNumber;
	}



	

}
