package com.jisu.securityproject.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jisu.securityproject.domain.AccountDto;
import com.jisu.securityproject.util.WebUtil;
import com.jisu.securityproject.security.token.AjaxAuthenticationToken;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
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
    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    private ObjectMapper objectMapper = new ObjectMapper();
    /**
     * url 과 매칭 되면 필터가 작동되게 구성 할 수  있다.
     */
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        //http메소드가 포스트가 아니거나 ajax가 아니면 예외 처리
        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        //사용자가 아이디랑 패스워드를 요청하면 그 값을 가져올텐데 json으로 옴
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }

        //인증처리는 ajax토큰을 만들어서 사용자 아이디 패스워드 정보를 담고 인증처리를 한다. AjaxAuthenticationToken의 첫번째 생성자
        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        //getAuthenticationManager에게 인증처리 위임한다.
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }
}
