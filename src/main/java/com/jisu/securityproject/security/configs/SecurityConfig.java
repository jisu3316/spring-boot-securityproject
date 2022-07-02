package com.jisu.securityproject.security.configs;

import com.jisu.securityproject.security.common.FormWebAuthenticationDetailsSource;
import com.jisu.securityproject.security.handler.FormCustomAccessDeniedHandler;
import com.jisu.securityproject.security.handler.FormCustomAuthenticationFailureHandler;
import com.jisu.securityproject.security.handler.FormCustomAuthenticationSuccessHandler;
import com.jisu.securityproject.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //UserDetailsService는 내가 구현한 CustomUserDetailsService이다.
    private final UserDetailsService userDetailsService;

    //username,password 이외의 파라미터 받아서 처리하는곳
    private final FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;

    //인증 성공 후 핸들러 커스텀
    private final FormCustomAuthenticationSuccessHandler formCustomAuthenticationSuccessHandler;

    //인증 실패 후 핸들러 커스텀
    private final FormCustomAuthenticationFailureHandler formCustomAuthenticationFailureHandler;

    //인증처리를 매니저에게 넘긴다.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//       auth.userDetailsService(userDetailsService);
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/users","/user/login/**","/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        .and()
                //커스텀 로그인 페이지
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource) //username,password 이외의 파라미터 받아서 처리하는곳
                .successHandler(formCustomAuthenticationSuccessHandler)  //인증성공후 redirect url
                .failureHandler(formCustomAuthenticationFailureHandler)  //인증 실패후 처리 핸들러
                .permitAll()
        .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler()); //인가 예외처리 핸들러

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //CustomUserDetailsService에서 UserDetails 반환해서 CustomAuthenticationProvider가 받아서 추가적인 검증하는 authenticationProvider
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormCustomAccessDeniedHandler accessDeniedHandler = new FormCustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }


}
