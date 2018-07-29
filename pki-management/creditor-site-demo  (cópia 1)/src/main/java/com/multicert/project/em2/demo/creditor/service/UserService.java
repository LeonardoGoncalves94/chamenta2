package com.multicert.project.em2.demo.creditor.service;

import com.multicert.project.em2.demo.creditor.model.User;

public interface UserService {
	public User findUserByEmail(String email);
	public void saveUser(User user);
	
	public void updateUser(User user);
}
