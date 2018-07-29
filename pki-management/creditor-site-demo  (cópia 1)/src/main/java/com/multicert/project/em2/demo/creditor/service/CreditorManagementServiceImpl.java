/**
 * 
 */
package com.multicert.project.em2.demo.creditor.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.em2.demo.creditor.model.CreditorConf;
import com.multicert.project.em2.demo.creditor.repository.CreditorConfRepository;

/**
 * @author ccardoso
 *
 */
@Service("creditorManagementService")
public class CreditorManagementServiceImpl implements CreditorManagementService {

	@Autowired
	private CreditorConfRepository creditorConfRepository;


	public CreditorConf getCreditorConfByCreditorId(String creditorId){

		return creditorConfRepository.findByCreditorId(creditorId);
	}


	public void saveOrUpdateCreditorConfData(CreditorConf conf){

		CreditorConf storedConf = this.getCreditorConfByCreditorId(conf.getCreditorId());

		if(storedConf != null){

			storedConf.setCreditorAddress(conf.getCreditorAddress());
			storedConf.setCreditorBankBic(conf.getCreditorBankBic());
			storedConf.setCreditorCountry(conf.getCreditorCountry());
			storedConf.setCreditorName(conf.getCreditorName());

		}else {
			storedConf = conf;
		}

		creditorConfRepository.save(conf);
	}


	@Override
	public List<CreditorConf> getAllCreditorsConf() {
		return creditorConfRepository.findAll();
	}


	@Override
	public void deleteCreditor(String creditorId) {
		creditorConfRepository.delete(creditorId);
		
	}
}
