package com.example.springjwt.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private final Long accessTokenExpiration;

    // 생성자: application.yml에 정의된 비밀키와 만료 시간을 주입받음
    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.access-token-expiration}") Long accessTokenExpiration) {
        // 비밀키를 HMAC-SHA 알고리즘에 맞는 SecretKey 객체로 변환
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
    }

    // 사용자 이름을 받아 AccessToken 생성
    public String createAccessToken(String username) {
        return createToken(username, accessTokenExpiration);
    }

    // 토큰 생성 공통 로직
    private String createToken(String username, Long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(username) // 토큰의 주체 (사용자 이름)
                .issuedAt(now) // 토큰 발급 시간
                .expiration(expiryDate) // 토큰 만료 시간
                .signWith(secretKey) // 서명에 사용할 비밀키
                .compact(); // JWT 문자열 생성
    }

    // 토큰에서 사용자 이름 추출
    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject();
    }

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            // 토큰 파싱 시 예외가 발생하지 않으면 유효한 토큰
            getClaims(token);
            return true;
        } catch (Exception e) {
            // 서명 불일치, 만료 등 모든 예외를 포함
            return false;
        }
    }

    // 토큰의 Payload(Claims) 부분 반환
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey) // 서명 검증에 사용할 키
                .build()
                .parseSignedClaims(token) // 토큰 파싱
                .getPayload();
    }
}