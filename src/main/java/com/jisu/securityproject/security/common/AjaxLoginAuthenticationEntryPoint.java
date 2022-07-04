package com.jisu.securityproject.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    //익명사용자가 인증이 필요한 자원에 접속했을때 예외필터가 AjaxLoginAuthenticationEntryPoint의 메서드 호출해서 클라이언트에 전달한다.
   @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
       response.setContentType("application/json");
       response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");

   }
}