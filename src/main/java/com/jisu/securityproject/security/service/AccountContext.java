package com.jisu.securityproject.security.service;

import com.jisu.securityproject.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

//사용자 정보를 담는 곳.

public class AccountContext extends User {

    private final Account account;
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
