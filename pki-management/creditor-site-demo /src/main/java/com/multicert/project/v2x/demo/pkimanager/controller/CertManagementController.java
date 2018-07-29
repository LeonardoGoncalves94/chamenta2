package com.multicert.project.v2x.demo.pkimanager.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Certificate;
import com.multicert.project.v2x.demo.pkimanager.model.Region;
import com.multicert.project.v2x.demo.pkimanager.repository.RegionRepository;
import com.multicert.project.v2x.demo.pkimanager.service.CaManagementService;
import com.multicert.project.v2x.demo.pkimanager.service.CertManagementService;
import com.multicert.project.v2x.demo.pkimanager.service.V2XService;
import com.multicert.v2x.IdentifiedRegions.Countries;
import com.multicert.v2x.IdentifiedRegions.Countries.CountryTypes;
import com.multicert.v2x.datastructures.base.CountryOnly;
import com.multicert.v2x.generators.*;

@Controller
public class CertManagementController {

	@Autowired
	private CertManagementService certManagementService;
	@Autowired
	private CaManagementService caManagementService;
	@Autowired
	private V2XService v2xService;
	@Autowired
	private RegionRepository regionRepository;
	
	@RequestMapping(value="/admin/certificate", method = RequestMethod.GET)
	public ModelAndView showCerts(){
		ModelAndView modelAndView = new ModelAndView();
		
		List<Certificate> certs = certManagementService.getAllCertificates();
		List <CA> rootSubjects = caManagementService.getSubjects("RootCa");
		List <CA> subSubjects = caManagementService.getSubjects("SubCa");
		List <CA> issuers = caManagementService.getIssuers();
		List <Region> countries = regionRepository.findAll();
	
		modelAndView.addObject("rootSubjects",rootSubjects);
		modelAndView.addObject("subSubjects",subSubjects);
		modelAndView.addObject("issuers",issuers);
		modelAndView.addObject("certs", certs);
		modelAndView.addObject("countries", countries);
		modelAndView.setViewName("admin/certificate");
		return modelAndView;
		
		
	}


	@RequestMapping(value = "/admin/addrootcert", method = RequestMethod.POST)
	public String addRootCert(@RequestParam("issuer") Long issuerId, @RequestParam("validity") Integer validity, @RequestParam(name ="countrylist") List <Region> countryList, 
			@RequestParam("confidence") Integer confidence, @RequestParam("assurance") Integer assurance, 
			@RequestParam("chainlength") Integer chainlength, @RequestParam("chainrange") Integer chainrange, final RedirectAttributes ra) throws IOException {
		
		CA issuer = caManagementService.getCaById(issuerId);
		
		if(issuer == null) {
			ra.addFlashAttribute("message", "specified issuer id does not exit");
			ra.addFlashAttribute("type", "danger");
		}
		
		certManagementService.saveRootCertificate(issuer, validity, countryList, confidence, assurance, chainlength, chainrange);
		
		ra.addFlashAttribute("message", "Certificate successfully added for: " + issuer.getCaName());
		ra.addFlashAttribute("type", "success");

		return "redirect:/admin/certificate";
	}
	
	@RequestMapping(value = "/admin/addsubcert", method = RequestMethod.POST)
	public String addSubCert(@RequestParam("subject") Long subjectId, @RequestParam("issuer") Long issuerId , @RequestParam("validity") Integer validity, 
			@RequestParam("countrylist") List<Region> countryList, @RequestParam("permissions") Integer psid,  @RequestParam("confidence") Integer confidence,
			@RequestParam("assurance") Integer assurance, @RequestParam("cracaid") String cracaid, @RequestParam("crlseries") Integer crlseries, @RequestParam("chainlength") Integer chainlength, @RequestParam("chainrange") Integer chainrange, 
			final RedirectAttributes ra) {
		
		CA subject = caManagementService.getCaById(subjectId);
		CA issuer = caManagementService.getCaById(issuerId);
		
		if(subject == null) {
			ra.addFlashAttribute("message", "specified subject id does not exit");
			ra.addFlashAttribute("type", "danger");
		}
		
		if(issuer == null) {
			ra.addFlashAttribute("message", "specified issuer id does not exit");
			ra.addFlashAttribute("type", "danger");
		}
		
		
		certManagementService.saveSubCertificate(issuer, subject, validity, countryList, psid, confidence, assurance, cracaid, crlseries, chainlength, chainrange);
		
		ra.addFlashAttribute("message", "Certificate successfully added for: " + issuer.getCaName());
		ra.addFlashAttribute("type", "success");

		return "redirect:/admin/certificate";
	}
		

}
