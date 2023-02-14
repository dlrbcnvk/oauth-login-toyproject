package com.tutorial.jsg.config.security;

import com.tutorial.jsg.oauth.token.AuthTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Bean
    public AuthTokenProvider jwtProvider() { return new AuthTokenProvider(); }
}
