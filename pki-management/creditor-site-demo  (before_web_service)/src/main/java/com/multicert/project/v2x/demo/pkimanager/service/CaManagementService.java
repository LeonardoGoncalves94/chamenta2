package com.multicert.project.v2x.demo.pkimanager.service;

import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CA;

public interface CaManagementService {

	public void saveOrUpdateCaData(CA ca);
	
	public CA getCaById(Long caId);
	
	public List<CA> getAllCas();
	
	public void deleteCa(Long caId);
	
	public List<CA> getSubjects(String ca_group);

	public List<CA> getIssuers();

}
