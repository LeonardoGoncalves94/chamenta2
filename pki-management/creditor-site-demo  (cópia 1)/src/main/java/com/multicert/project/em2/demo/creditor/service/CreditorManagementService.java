/**
 * 
 */
package com.multicert.project.em2.demo.creditor.service;

import java.util.List;

import com.multicert.project.em2.demo.creditor.model.CreditorConf;

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
