package com.jisu.securityproject.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jisu.securityproject.domain.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//비동기 방식의 ajax 인증 성공했을 때의 핸들러

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //비동기 응답 할거기때문에 상태코드와 json타입을 넣어준다.
        Account account = (Account) authentication.getPrincipal();// 인증의 최종 성공한 객체안에있는 Account를 여기에 저앟했다.AjaxAuthenticationProvider에서 Authenticate에서 리턴했다.

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getWriter(), account);

    }
}
