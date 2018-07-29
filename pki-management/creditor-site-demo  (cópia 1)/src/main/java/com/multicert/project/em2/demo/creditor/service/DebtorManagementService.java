/**
 * 
 */
package com.multicert.project.em2.demo.creditor.service;

import java.util.List;

import com.multicert.project.em2.demo.creditor.model.DebtorBank;

/**
 * @author ccardoso
 *
 */
public interface DebtorManagementService {
	
	public int saveOrUpdateDebtorBank(DebtorBank bank);
	
	public List<DebtorBank> gellAllDebtorBanks();
	
	public void addDebtorBank(Long userId, DebtorBank bank);
	

}
