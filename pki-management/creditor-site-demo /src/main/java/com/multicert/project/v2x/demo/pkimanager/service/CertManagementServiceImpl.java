package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Certificate;
import com.multicert.project.v2x.demo.pkimanager.model.Region;
import com.multicert.project.v2x.demo.pkimanager.repository.CertRepository;

@Service("CertManagementService")
public class CertManagementServiceImpl implements CertManagementService {

	@Autowired
	CertRepository certRepository;
	@Autowired
	V2XService v2xService;

	private void saveCertificateData(Certificate cert) {
		Certificate currentCert = this.getCertById(cert.getCertId());
		currentCert = cert;
		certRepository.save(currentCert);
	}

	@Override
	public Certificate getCertById(Long certId) {
		return certRepository.findBycertId(certId);
	}

	@Override
	public List<Certificate> getAllCertificates() {
		return certRepository.findAll();
	}

	@Override
	public void deleteCertificate(Long certID) {
		certRepository.delete(certID);
		
	}	
	
	/**
	 * Method that generates a Root CA certificate (using v2xervice) and stores its information on the database
	 */
	@Override
	public void saveRootCertificate(CA issuer, Integer validity,  List <Region> countryList, Integer confidence, Integer assurance,
			Integer minChain, Integer chainRange ) throws IOException {
		//Only a test
		for(Region r : countryList){
			System.out.println(r.getRegionName());
		}
		
		v2xService.genRootCertificate(issuer, validity, countryList, confidence, assurance, minChain, chainRange);
		
		//Save the certificate in the database
		Certificate rootCert = new Certificate(issuer, validity, confidence, assurance, minChain, chainRange);	
		saveCertificateData(rootCert);
	}
	
	/**
	 * Apply Business logic needed to create a certificate (the encoded value) to be added to the database. Uses v2x jar
	 */
	@Override
	public void saveSubCertificate(CA issuer, CA subject, Integer validity, List <Region> countryList, Integer psid, Integer confidence, Integer assurance, String cracaid, Integer crlseries, Integer chainlength, Integer chainrange) {
		
		Certificate subCert = new Certificate(issuer, subject, validity, psid, confidence, assurance, cracaid, crlseries, chainlength, chainrange);
		saveCertificateData(subCert);
	}
	
	

}
