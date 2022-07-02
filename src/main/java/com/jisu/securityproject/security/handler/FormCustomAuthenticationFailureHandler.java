package com.jisu.securityproject.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//인증 실패 했을때의 핸들러 스프링시큐리티가 제공하는 SimpleUrlAuthenticationFailureHandler 을 상속받아 구현한다
@Component
public class FormCustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    /**
     * 인증예외는 인증을 검증할때 인증에 실패하게되면 인증예외가 발생하게된다. 유저 디테일서비스에서 아이디가없거나 패스워드가 일치하지않으면 생기는 예외이다.
     * 인증필터가  onAuthenticationFailure 호출해 처리한다.
     * @param request the request during which the authentication attempt occurred.
     * @param response the response.
     * @param exception the exception which was thrown to reject the authentication
     * request.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        
        String errorMessage = "Invalid Username or Password";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

        super.onAuthenticationFailure(request, response, exception);
    }
}
