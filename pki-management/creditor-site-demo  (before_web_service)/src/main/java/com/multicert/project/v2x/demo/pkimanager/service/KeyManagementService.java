package com.multicert.project.v2x.demo.pkimanager.service;

import java.util.List;

import com.multicert.project.v2x.demo.pkimanager.model.CA;
import com.multicert.project.v2x.demo.pkimanager.model.Key;

public interface KeyManagementService {

	public Key getKeyById(Long keyId);
	
	public List<Key> getAllKeys();
	
	public void deleteKey(Long keyId);

	void saveKey(Key key) throws Exception;

	void changeKey(Key key) throws Exception;
	
}
