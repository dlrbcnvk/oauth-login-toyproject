package com.tutorial.jsg.config.security;

import com.tutorial.jsg.api.repository.UserRefreshTokenRepository;
import com.tutorial.jsg.oauth.entity.RoleType;
import com.tutorial.jsg.oauth.exception.RestAuthenticationEntryPoint;
import com.tutorial.jsg.oauth.filter.TokenAuthenticationFilter;
import com.tutorial.jsg.oauth.handler.OAuth2AuthenticationSuccessHandler;
import com.tutorial.jsg.oauth.handler.TokenAccessDeniedHandler;
import com.tutorial.jsg.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.tutorial.jsg.oauth.service.CustomOAuth2UserService;
import com.tutorial.jsg.oauth.token.AuthTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthTokenProvider tokenProvider;
    private final CustomOAuth2UserService oAuth2UserService;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;
    private final UserRefreshTokenRepository userRefreshTokenRepository;



    /**
     * TODO
     * 설정 클래스 공식문서 정독할 것
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .accessDeniedHandler(tokenAccessDeniedHandler)
            .and()
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/api/**").hasAnyAuthority(RoleType.USER.getCode())
                .antMatchers("/api/**/admin/**").hasAnyAuthority(RoleType.ADMIN.getCode())
                .anyRequest().authenticated()
            .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
            .and()
                .successHandler(oAuth2AuthenticationSuccessHandler());

        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * security 설정 시, 사용할 인코더 설정
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 토큰 필터 설정
     */
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

    /**
     * 쿠키 기반 인가 Repository
     * 인가 응답을 연계하고 검증할 때 사용
     */
    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    /**
     * OAuth 인증 성공 핸들러
     */
    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(
                tokenProvider,
                userRefreshTokenRepository
        );
    }


}
