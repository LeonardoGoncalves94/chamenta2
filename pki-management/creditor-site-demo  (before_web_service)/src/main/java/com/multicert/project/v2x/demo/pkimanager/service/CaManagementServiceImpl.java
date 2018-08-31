package com.multicert.project.v2x.demo.pkimanager.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Key;
import com.multicert.project.v2x.demo.pkimanager.repository.CaRepository;

@Service("caManagementService")
public class CaManagementServiceImpl implements CaManagementService {

	@Autowired
	private CaRepository caRepository;
	
	public void saveOrUpdateCaData(CA ca){

		CA storedCa = this.getCaById(ca.getCaId());

		if(storedCa != null){
			storedCa.setCaName(ca.getCaName());
			storedCa.setCaCountry(ca.getCaCountry());
			storedCa.setCaType(ca.getCaType());
			storedCa.setKeys(ca.getKeys());
		}else {
			storedCa = ca;
		}

		caRepository.save(storedCa);
	}

	public CA getCaById(Long caId){ 
		return caRepository.findBycaId(caId);
	}

	@Override
	public List<CA> getAllCas() {
		return caRepository.findAll();
	}

	@Override
	public void deleteCa(Long caId) {
		caRepository.delete(caId);	
	}
	/**
	 * This method filters the list of possible subject CAs (CAs with encryption keys associated) and returns only the ones which don't have already a certificate associated
	 * A CA is considered  a valid subject subject if it does have an encryption key and not a subject of any certificate. 
	 */
	@Override
	public List<CA> getSubjects(String ca_group) {
		List <CA> subjects = caRepository.findSubjects(ca_group);
		List <CA> validSubjects = new ArrayList<CA>();
		
		for(CA ca : subjects) {
			if(ca.getCertificate() == null) {
				if(!validSubjects.contains(ca)) //avoid duplicates
				validSubjects.add(ca);
			}
		}
		
		return validSubjects;
		
	}
	
	@Override
	public List<CA> getIssuers() {
		return caRepository.findIssuers();
	}
	
}
