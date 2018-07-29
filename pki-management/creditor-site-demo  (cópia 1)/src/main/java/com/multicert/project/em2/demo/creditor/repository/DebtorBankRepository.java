/**
 * 
 */
package com.multicert.project.em2.demo.creditor.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.multicert.project.em2.demo.creditor.model.DebtorBank;

/**
 * @author ccardoso
 *
 */
@Repository("debtorBankRepository")
public interface DebtorBankRepository extends JpaRepository<DebtorBank, Integer> {
	
	DebtorBank findByBankBic(String bankBic);

}
