package com.jisu.securityproject.repository;

import com.jisu.securityproject.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
