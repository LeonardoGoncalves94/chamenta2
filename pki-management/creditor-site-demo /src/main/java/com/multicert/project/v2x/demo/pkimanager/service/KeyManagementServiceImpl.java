package com.multicert.project.v2x.demo.pkimanager.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.multicert.project.v2x.demo.pkimanager.DemoApplication;
import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Key;
import com.multicert.project.v2x.demo.pkimanager.repository.KeyRepository;
import com.multicert.v2x.datastructures.base.Signature;


@Service("KeyManagementService")

public class KeyManagementServiceImpl implements KeyManagementService {

	@Autowired
	KeyRepository keyRepository;
	@Autowired
	V2XService v2xService;
	
	private void saveOrUpdateKeyData(Key key) {
		
		Key storedKey = this.getKeyById(key.getKeyId());

		if(storedKey != null){
			storedKey.setAlias(key.getAlias());
		}else {
			storedKey = key;
		}

		keyRepository.save(storedKey);
	}

	@Override
	public Key getKeyById(Long keyId) {
		return keyRepository.findBykeyId(keyId);
	}

	@Override
	public List<Key> getAllKeys() {
		return keyRepository.findAll();
	}

	@Override
	public void deleteKey(Long keyId) {
		keyRepository.delete(keyId);	
	}
	
	@Override
	public void changeKey(Key key) throws Exception{	
	// chama codigo para mudar o alias da key
	}
	
	
	@Override
	public void saveKey(String alias, CA ca, String algorithm) throws Exception{
		
		//generate the key pair
		v2xService.genKey(alias, algorithm);
		
		//save the key pair data on the database
		Key key = new Key(alias, algorithm, ca, getKeyType(algorithm));
		saveOrUpdateKeyData(key);
	}
	
	/**
	 * Help method that based on the key algorithm returns the type of key (signature or encryption key)
	 */
	private String getKeyType(String algorithm)
	{
		if(algorithm.equals("ECDSA-Nist") || algorithm.equals("ECDSA-Brainpool")) {
			return "Signature";
		}
		
		else return "Encryption";
	}

}
