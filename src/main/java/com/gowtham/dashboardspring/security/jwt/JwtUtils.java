package com.gowtham.dashboardspring.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.gowtham.dashboardspring.security.services.UserDetailsImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${gowtham.app.jwtSecret}")
    private String jwtSecret;

    @Value("${gowtham.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS256, key())
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        try {
            Claims body = Jwts.parser().setSigningKey(key()).build().parseSignedClaims(token).getPayload();
            return body.getSubject();
        } catch (Exception e) {
            logger.error("Error parsing JWT token: {}", e.getMessage());
            return null; // Handle the error appropriately
        }
    }

    public boolean validateJwtToken(String authToken) {
        try {
            ((JwtParserBuilder) Jwts.builder()).setSigningKey(key()).build().parseClaimsJws(authToken);
            return true; // Token is valid
        } catch (Exception e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
            return false; // Token is invalid
        }
    }
    public SecretKey generateKey() {
        return (SecretKey) key();
    }
//    public static SecretKey generateKey() {
//        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
//    }
}
