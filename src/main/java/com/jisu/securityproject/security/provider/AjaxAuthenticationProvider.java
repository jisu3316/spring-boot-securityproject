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
        String loginId = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !secretKey.equals("secret")) {
            throw new InsufficientAuthenticationException("Invalid Secret");
        }


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
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
