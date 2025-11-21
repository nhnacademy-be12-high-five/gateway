package com.nhnacademy.gateway.jwt;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final Long accessExpirationTime;
    private final Long refreshExpirationTime;
    private final SecretKey secretKey;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiration_time}") Long accessExpirationTime,
                   @Value("${jwt.refresh_expiration_time}") Long refreshExpirationTime) { // ★ 2개 받기

        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpirationTime = accessExpirationTime;
        this.refreshExpirationTime = refreshExpirationTime;
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Long getUserId(String token) {
        return Long.parseLong(getClaims(token).getSubject());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            // log.error("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            // log.error("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            // log.error("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            // log.error("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

}
