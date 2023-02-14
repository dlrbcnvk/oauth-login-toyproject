package com.tutorial.jsg;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


public class JWTTest {



    @Test
    public void jjwt_test() {

        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS512);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Date now = new Date();

        // Make JWS
        String jwsString = Jwts.builder()
                .setIssuer("me")
                .setSubject("Bob")
                .setAudience("you")
                .signWith(privateKey)
                .setExpiration(new Date(now.getTime() + 604800000))
                .setIssuedAt(now)
                .setId(UUID.randomUUID().toString())
                .compact();

        String jwsString2 = Jwts.builder()
                .setIssuer("me")
                .setSubject("Bob")
                .setAudience("you")
                .signWith(privateKey)
                .setExpiration(new Date(now.getTime() + 604800000))
                .setIssuedAt(now)
                .setId(UUID.randomUUID().toString())
                .compact();

        Assertions.assertThat(jwsString).isNotEqualTo(jwsString2);


        // Read JWS
        Jws<Claims> jws;
        long seconds = 3 * 60; // 3 minutes

        try {
            jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .setAllowedClockSkewSeconds(seconds)
                    .requireSubject("Bob")
                    .build()
                    .parseClaimsJws(jwsString);
        } catch (MissingClaimException mce) {

        } catch (IncorrectClaimException ice) {

        } catch (JwtException e) {

        }

    }

    @Test
    public void jjwt_test_hmac() {

        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

        Date now = new Date();

        // Make JWS
        String jwsString = Jwts.builder()
                .setIssuer("me")
                .setSubject("Bob")
                .setAudience("you")
                .signWith(secretKey)
                .setExpiration(new Date(now.getTime() + 604800000))
                .setIssuedAt(now)
                .setId(UUID.randomUUID().toString())
                .compact();

        String jwsString2 = Jwts.builder()
                .setIssuer("me")
                .setSubject("Bob")
                .setAudience("you")
                .signWith(secretKey)
                .setExpiration(new Date(now.getTime() + 604800000))
                .setIssuedAt(now)
                .setId(UUID.randomUUID().toString())
                .compact();

        Assertions.assertThat(jwsString).isEqualTo(jwsString2);


        // Read JWS
        Jws<Claims> jws;
        long seconds = 3 * 60; // 3 minutes

        try {
            jws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .setAllowedClockSkewSeconds(seconds)
                    .requireSubject("Bob")
                    .build()
                    .parseClaimsJws(jwsString);
        } catch (MissingClaimException mce) {

        } catch (IncorrectClaimException ice) {

        } catch (JwtException e) {

        }

    }
}
