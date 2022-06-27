package com.jisu.securityproject.service;

import com.jisu.securityproject.domain.Account;
import com.jisu.securityproject.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public void createUser(Account account) {
        account.encodPassword(passwordEncoder.encode(account.getPassword()));
        userRepository.save(account);
    }
}
