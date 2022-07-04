package com.jisu.securityproject.security.provider;

import com.jisu.securityproject.security.common.FormWebAuthenticationDetails;
import com.jisu.securityproject.security.service.AccountContext;
import com.jisu.securityproject.security.token.AjaxAuthenticationToken;
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

/**
 * Ajax이지만 form 인증 방식과 같다.
 * 다른점은 인증객체가 다르다
 */
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    /**
     * 검증을 위한 구현
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     */
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        //userDetailsService 구현한 User를 상속받은 custom 객체 AccountContext
        //CustomUserDetailsService 여기서 accountContext 잘 건내받은거면 아이디는 검증된거다.
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        //패스워드가 일치하지 않으면 인증실패
        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

//        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
//        if (secretKey == null || !secretKey.equals("secret")) {
//            throw new InsufficientAuthenticationException("Invalid Secret");
//        }


        return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    /**
     * 파라미터로 전달되는 클래스의 타입과 클래스가 사용하고자하는 토큰이 일치할때.
     *  authentication 타입과 CustomAuthenticationProvider가 사용하고자하는 토큰타입이 일치할때 프로바이더 인증처리를 할 수 있게
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
