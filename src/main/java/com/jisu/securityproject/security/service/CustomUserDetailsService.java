package com.jisu.securityproject.security.service;

import com.jisu.securityproject.domain.Account;
import com.jisu.securityproject.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
//db연동 인증처리 완료.
//사용자 정보를 가져오는곳
@Service("userDetailsService")
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username); // 사용자 계정이 존재하는지 검사

        if (account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException"); //없으면 널Exception
        }

        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));

        //account가 널이 아니면 UserDetails타입의 객체를 반환한다. 스프링 시큐리티에서 구현한 구현체가 User이다. 우리는  AccountContext이다.
        AccountContext accountContext = new AccountContext(account, roles);

        return accountContext;//UserDetails 반환 이 객체를 받아서 추가적인 검증하는 authenticationProvider구현해야함
    }
}
