package com.multicert.project.v2x.demo.pkimanager.controller;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.service.CaManagementService;


@Controller
public class CaManagementController {

	@Autowired
	private CaManagementService caManagementService;



	@RequestMapping(value="/admin/ca", method = RequestMethod.GET)
	public ModelAndView showCAs(){
		ModelAndView modelAndView = new ModelAndView();

		List<CA> cas = caManagementService.getAllCas();
		modelAndView.addObject("cas",cas);
		modelAndView.addObject("allTypes", getTypes());
		modelAndView.setViewName("admin/ca");
		return modelAndView;
	}
	
	@RequestMapping(value="/user/user-ca", method = RequestMethod.GET)
	public ModelAndView showUserCAs(){
		ModelAndView modelAndView = new ModelAndView();

		List<CA> cas = caManagementService.getAllCas();
		modelAndView.addObject("cas",cas);
		modelAndView.setViewName("user/user-ca");
		return modelAndView;
	}
	
	@RequestMapping(value = "/admin/editca", method = RequestMethod.POST)
	public String editCa(@RequestParam("caId") Long caId, @RequestParam("caCountry") String caCountry , final RedirectAttributes ra) {
			
		CA currentCa = caManagementService.getCaById(caId);
		
		if(currentCa == null) {
			ra.addFlashAttribute("message", "Specified CA does not exist");
			ra.addFlashAttribute("type", "danger");
		}
		
		currentCa.setCaCountry(caCountry);
		
		try {
			caManagementService.saveOrUpdateCaData(currentCa);

			ra.addFlashAttribute("message", "CA data updated");
			ra.addFlashAttribute("type", "success");

		} catch (Exception e) {
			
			e.printStackTrace();
		}

	
		return "redirect:/admin/ca";
	}

	@RequestMapping(value = "/admin/addca", method = RequestMethod.POST)
	public String addCa(@RequestParam("caName") String caName, @RequestParam("caCountry") String caCountry, @RequestParam("caType") String caType, final RedirectAttributes ra) {
		
		CA ca = new CA(caName, caCountry, caType, getGroup(caType));

		caManagementService.saveOrUpdateCaData(ca);

		ra.addFlashAttribute("message", "Certification authority successfully added");
		ra.addFlashAttribute("type", "success");
			
		return "redirect:/admin/ca";
	}
	
	/**
	 * Help method to display the possible types of CA 
	 */
	private List<String> getTypes(){
		List<String> types = new ArrayList<>();
		types.add("Root");
		types.add("Enrollment");
		types.add("Authorization");
		return types;
	}
	
	/**
	 * Help method to flag CAs as Root CA or Sub CA (authorization authorities and enrollment authorities)
	 */
	private String getGroup(String caType){
		if(caType.equals("Root")) {
			return "RootCa";
		}
		return "SubCa";
	}
	

}
