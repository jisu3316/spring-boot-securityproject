package com.jisu.securityproject.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jisu.securityproject.domain.AccountDto;
import com.jisu.securityproject.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/**
 * ajax 요청 필터
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * url 설정하면 사용자가 이 url로 요청해을때 매칭되면 필터가 호출됨.
     */
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("username or Password is empty");
        }

        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());


        return getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 사용자가 요청할때 헤더에 값을 보내는데 그 값과 같은지 안 같은지 약속을 정해준다.
     */
    private boolean isAjax(HttpServletRequest request) {

        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }
        return false;
    }
}
