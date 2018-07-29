package com.multicert.project.v2x.demo.pkimanager.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Region;


@Repository("regionRepository")
public interface RegionRepository extends JpaRepository<Region, Long>{
	
	public Region findByregionId(Long regionId);
	
	public Region findByregionNumber(Long regionNumber);
	
	public Region findByregionName(String regionName);
	
}
