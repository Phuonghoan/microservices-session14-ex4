package org.example.identityservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.example.identityservice.entity.User;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    private final Key signingKey;
    private final long accessTokenExpiration;

    public JwtUtil(
            @Value("${app.jwt.secret}") String jwtSecret,
            @Value("${app.jwt.access-token-expiration}")
            long accessTokenExpiration
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);

        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpiration = accessTokenExpiration;
    }

    // Tạo Access Token
    public String generateAccessToken(User user) {

        Date now = new Date();

        Date expiration = new Date(
                now.getTime() + accessTokenExpiration
        );

        return Jwts.builder()

                // JWT ID duy nhất
                .setId(UUID.randomUUID().toString())

                // Username
                .setSubject(user.getUsername())

                // Role
                .claim("role", user.getRole())

                // Thời gian tạo
                .setIssuedAt(now)

                // Thời gian hết hạn
                .setExpiration(expiration)

                // Chữ ký JWT
                .signWith(
                        signingKey,
                        SignatureAlgorithm.HS256
                )

                .compact();
    }

    // Giải mã và xác minh JWT
    public Claims extractClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}