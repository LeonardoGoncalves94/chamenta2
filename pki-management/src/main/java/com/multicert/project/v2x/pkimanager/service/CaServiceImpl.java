package com.multicert.project.v2x.pkimanager.service;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.pkimanager.model.CA;
import com.multicert.project.v2x.pkimanager.model.Certificate;
import com.multicert.project.v2x.pkimanager.model.Key;
import com.multicert.project.v2x.pkimanager.model.Request;
import com.multicert.project.v2x.pkimanager.model.Response;
import com.multicert.project.v2x.pkimanager.repository.CaRepository;
import com.multicert.v2x.cryptography.BadContentTypeException;
import com.multicert.v2x.cryptography.DecryptionException;
import com.multicert.v2x.cryptography.ImcompleteRequestException;
import com.multicert.v2x.cryptography.IncorrectRecipientException;
import com.multicert.v2x.cryptography.InvalidSignatureException;
import com.multicert.v2x.cryptography.UnknownItsException;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.EnrollmentResonseCode;
import com.multicert.v2x.datastructures.message.encrypteddata.RecipientInfo;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

@Service("caManagementService")
public class CaServiceImpl implements CaService {

	@Autowired
	private CaRepository caRepository;
	@Autowired
	private V2XService v2xService;
	
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
	
	public CA getCaByName(String caName){ 
		return caRepository.findBycaName(caName);
	}

	@Override
	public List<CA> getAllCas() {
		return caRepository.findAll();
	}

	@Override
	public void deleteCa(Long caId) {
		caRepository.delete(caId);	
	}

	@Override
	public EtsiTs103097Data validateEcRequest(byte[] encryptedRequest, PublicKey canonicalKey, String caName)throws Exception{
			
		CA destCa = getCaByName(caName);
		Certificate destinationCertificate = destCa.getCertificate();
		Key encKeyPair = destCa.getEncryptionKey();
		Key sigKeyPair = destCa.getSignatureKey();
		
		return v2xService.processEcRequest(encryptedRequest, destinationCertificate, encKeyPair, canonicalKey, sigKeyPair);		
		
	}
	

	/**
	 * Help method that verifies if a CA exists, has keys and a certificate associated
	 * @param caName
	 * @return true if the CA is ready, false if not
	 */
	public boolean isReady(String caName) 
	{
		CA ca = getCaByName(caName);
		if(ca == null) 
		{
			return false;
		}
		
		if(ca.getEncryptionKey() != null && ca.getCertificate() != null && ca.getSignatureKey() != null)
		{
			return true;
		}
		return false;
	}
	
	/**
	 * This method filters the list of possible subject CAs (CAs with encryption keys associated) and returns only the ones which don't have already a certificate associated
	 * A CA is considered  a valid subject subject if it does have an encryption key and not a subject of any certificate. 
	 */
	@Override
	public List<CA> getValidSubjects(String ca_group) {
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
	public List<CA> getValidIssuers() {
		return caRepository.findIssuers();
	}
}
