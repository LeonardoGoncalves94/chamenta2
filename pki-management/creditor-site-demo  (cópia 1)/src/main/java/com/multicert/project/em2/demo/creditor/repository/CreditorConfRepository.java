/**
 * 
 */
package com.multicert.project.em2.demo.creditor.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.multicert.project.em2.demo.creditor.model.CreditorConf;

/**
 * @author ccardoso
 *
 */
@Repository("creditorConfRepository")
public interface CreditorConfRepository extends JpaRepository<CreditorConf, String>{

	CreditorConf findByCreditorId(String creditorId);
}
