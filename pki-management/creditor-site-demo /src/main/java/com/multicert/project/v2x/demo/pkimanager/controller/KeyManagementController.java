package com.multicert.project.v2x.demo.pkimanager.controller;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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

import com.multicert.project.v2x.demo.pkimanager.DemoApplication;
import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Key;
import com.multicert.project.v2x.demo.pkimanager.service.CaManagementService;
import com.multicert.project.v2x.demo.pkimanager.service.KeyManagementService;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.Signature;


@Controller
public class KeyManagementController {

	@Autowired
	private KeyManagementService keyManagementService;
	@Autowired
	private CaManagementService caManagementService;



	@RequestMapping(value="/admin/key", method = RequestMethod.GET)
	public ModelAndView showCAs(){
		ModelAndView modelAndView = new ModelAndView();

		List<Key> keys = keyManagementService.getAllKeys();
		List<CA> cas = caManagementService.getAllCas();
		modelAndView.addObject("cas", cas);
		modelAndView.addObject("keys",keys);
		modelAndView.addObject("allAlgorithms", getAlgorithms());
		modelAndView.setViewName("admin/key");
		
		return modelAndView;
	}
	
	//TODO falta meter a trcar no alias da chave no keystore
	@RequestMapping(value = "/admin/editkey", method = RequestMethod.POST)
	public String editKey(@RequestParam("keyId") Long keyId, @RequestParam("alias") String alias, final RedirectAttributes ra) {
		
	
		Key currentKey = keyManagementService.getKeyById(keyId);
		
		if(currentKey == null) {
			ra.addFlashAttribute("message", "Specified key does not exist");
			ra.addFlashAttribute("type", "danger");
		}
		
		currentKey.setAlias(alias);
		
		try {
			keyManagementService.changeKey(currentKey); // TODO implement here

			ra.addFlashAttribute("message", "CA data updated");
			ra.addFlashAttribute("type", "success");

		} catch (Exception e) {
			
			e.printStackTrace();
		}

	
		return "redirect:/admin/key";
	}

	@RequestMapping(value = "/admin/addkey", method = RequestMethod.POST)
	public String addKey(@RequestParam("alias") String alias, @RequestParam("algorithm") String algorithm, @RequestParam("ca") Long caId, final RedirectAttributes ra) throws Exception {
		
		CA ca = caManagementService.getCaById(caId);
		if (ca == null) {
			ra.addFlashAttribute("message", "specified CA id does not exit");
			ra.addFlashAttribute("type", "danger");
		}
		
		try {
			
		keyManagementService.saveKey(alias, ca, algorithm);
		
		ra.addFlashAttribute("message", "Key successfully added for "+ ca.getCaName());
		ra.addFlashAttribute("type", "success");
		} catch(Exception e) {
			e.printStackTrace();
		}
		return "redirect:/admin/key";
	}
	
	
	/**
	 * Help method that lists the possible algorithms for the keys
	 */
	private List<String> getAlgorithms(){
		List<String> algorithms = new ArrayList<>();
		algorithms.add("ECIES-Nist");
		algorithms.add("ECIES-Brainpool");
		algorithms.add("ECDSA-Nist");
		algorithms.add("ECDSA-Brainpool");
		return algorithms;
	}
	

	
	

}
