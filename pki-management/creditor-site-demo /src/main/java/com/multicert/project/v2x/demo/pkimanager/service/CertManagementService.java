package com.multicert.project.v2x.demo.pkimanager.service;

import java.io.IOException;
import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Certificate;
import com.multicert.project.v2x.demo.pkimanager.model.Region;

public interface CertManagementService {

	public Certificate getCertById(Long certId);
	
	public List<Certificate> getAllCertificates();
	
	public void deleteCertificate(Long certID);
	
	/**
	 * Method that creates a valid Root CA certificate, and stores its infomation on the database
	 * @throws IOException 
	 */
	public void saveRootCertificate(CA issuer, Integer validity,  List <Region> countryList, Integer confidence, Integer assurance,
			Integer minChain, Integer chainRange) throws IOException;
	/**
	 * Method that creates a valid Sub CA certificate, and stores its infomation on the database
	 */
	void saveSubCertificate(CA issuer, CA subject, Integer validity, List <Region> countryList, Integer psid, Integer confidence,
			Integer assurance, String cracaid, Integer crlseries, Integer chainlength, Integer chainrange);
	
}
