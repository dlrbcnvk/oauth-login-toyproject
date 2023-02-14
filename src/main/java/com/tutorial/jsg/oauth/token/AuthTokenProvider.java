package com.tutorial.jsg.oauth.token;

import com.tutorial.jsg.oauth.exception.TokenValidFailedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.security.Key;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
public class AuthTokenProvider {

    private final KeyPair keyPair;
    private static final String AUTHORITIES_KEY = "role";

    public AuthTokenProvider() {
        this.keyPair = Keys.keyPairFor(SignatureAlgorithm.RS512);
    }

    public AuthToken createAuthToken(String id, Date expiry) {
        return new AuthToken(id, expiry, keyPair);
    }

    public AuthToken createAuthToken(String id, String role, Date expiry) {
        return new AuthToken(id, role, expiry, keyPair);
    }

    public AuthToken createAuthToken(String token) {
        return new AuthToken(token, keyPair.getPrivate(), keyPair.getPublic());
    }

    public AuthToken convertAuthToken(String token) {
        return new AuthToken(token, keyPair.getPrivate(), keyPair.getPublic());
    }

    public Authentication getAuthentication(AuthToken authToken) {

        if (authToken.validate()) {

            Claims claims = authToken.getTokenClaims();
            Collection<? extends GrantedAuthority> authorities =
                    Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

            User principal = new User(claims.getSubject(), "", authorities);

            return new UsernamePasswordAuthenticationToken(principal, authToken, authorities);
        } else {
            throw new TokenValidFailedException();
        }
    }
}
