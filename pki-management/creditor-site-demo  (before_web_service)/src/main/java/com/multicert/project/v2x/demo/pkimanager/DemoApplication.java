package com.multicert.project.v2x.demo.pkimanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.multicert.v2x.cryptography.CryptoHelper;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) throws Exception {	
		SpringApplication.run(DemoApplication.class, args);
	}
}
