package com.jisu.securityproject.security.service;

import com.jisu.securityproject.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

//스프링 시큐리티가 제공하는 UserDetails 인터페이스를 구현한 User 클래스를 상속받았다.
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
