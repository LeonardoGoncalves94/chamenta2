package com.multicert.project.v2x.demo.pkimanager.service;

import com.multicert.project.v2x.demo.pkimanager.model.User;

public interface UserService {
	public User findUserByEmail(String email);
	public void saveUser(User user);
	
	public void updateUser(User user);
}
