package com.jisu.securityproject.security.provider;

import com.jisu.securityproject.security.common.FormWebAuthenticationDetails;
import com.jisu.securityproject.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

//UserDetails 반환 이 객체를 받아서 추가적인 검증하는 authenticationProvider구현해야함
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {



    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    /**
     * 검증을 위한 구현
     * authentication 는 authenticationManager로 부터 받는 인증객체이다. 사용자 정보가 담겨져있다.
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     */
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        //userDetailsService 구현한 User를 상속받은 custom 객체 AccountContext
        //CustomUserDetailsService 여기서 accountContext 잘 건내받은거면 아이디는 검증된거다.
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        //패스워드가 일치하지 않으면 인증실패
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        //인증 요청시 username, password 이외의 파라미터를 받아 처리하는 곳
        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !secretKey.equals("secret")) {
            throw new InsufficientAuthenticationException("Invalid Secret");
        }

        //UsernamePasswordAuthenticationToken 두번쨰 생성자의 인증객체
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        return authenticationToken;
    }

    /**
     * 파라미터로 전달되는 클래스의 타입과 클래스가 사용하고자하는 토큰이 일치할때.
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
