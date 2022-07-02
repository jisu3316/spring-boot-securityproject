package com.jisu.securityproject.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//인증성공후 처리하는 핸들러 시큐리티에서 제공하는 success SimpleUrlAuthenticationSuccessHandler 를 구현해서 만든다.
@Component
public class FormCustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    //성공전 요청했던 url을 가져올수있다
    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    /**
     * 요청캐시 객체가있다. 사용자가 인증을성공한다음에 이동할 페이지로 설정을한다.
     * 사용자가 인증을 성공하지못하고 로그인페이지로 가고 다시 원래가고자했던 페이지로 가고싶을때 캐시로 원래가려했던 url로 가는처리
     * @param request the request which caused the successful authentication
     * @param response the response
     * @param authentication the <tt>Authentication</tt> object which was created during
     * the authentication process.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");
        //인증을 성공하기전 사용자가 가려고한 url을 캐시에서 꺼내온다.
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }

    }
}
