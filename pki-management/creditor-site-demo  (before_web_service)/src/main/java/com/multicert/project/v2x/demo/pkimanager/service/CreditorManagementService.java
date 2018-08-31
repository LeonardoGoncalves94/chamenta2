/**
 * 
 */
package com.multicert.project.v2x.demo.pkimanager.service;

import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CreditorConf;

/**
 * @author ccardoso
 *
 */
public interface CreditorManagementService {

	
	public CreditorConf getCreditorConfByCreditorId(String creditorId);
	
	public void saveOrUpdateCreditorConfData(CreditorConf conf);
	
	public List<CreditorConf> getAllCreditorsConf();
	
	public void deleteCreditor(String creditorId);
	
}
