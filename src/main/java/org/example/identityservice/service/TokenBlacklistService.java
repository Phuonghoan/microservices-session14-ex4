package org.example.identityservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

import org.example.identityservice.util.JwtUtil;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;

@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private final JwtUtil jwtUtil;

    public TokenBlacklistService(
            StringRedisTemplate redisTemplate,
            JwtUtil jwtUtil
    ) {
        this.redisTemplate = redisTemplate;
        this.jwtUtil = jwtUtil;
    }

    // =====================================
    // LOGOUT: ĐƯA JWT VÀO BLACKLIST
    // =====================================

    public void logout(String token) {

        // 1. Giải mã và xác minh JWT
        Claims claims = jwtUtil.extractClaims(token);

        // 2. Lấy JWT ID
        String jti = claims.getId();

        // 3. Lấy thời gian hết hạn
        Instant expiration = claims.getExpiration().toInstant();

        if (jti == null || jti.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Token không có JTI hợp lệ"
            );
        }

        // 4. Tính thời gian còn lại của JWT
        long remainingTime = Duration.between(
                Instant.now(),
                expiration
        ).toMillis();

        if (remainingTime <= 0) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Access Token đã hết hạn"
            );
        }

        // 5. Tạo Redis Key
        String redisKey = "blacklist:" + jti;

        // 6. Lưu Redis với TTL bằng thời gian còn lại
        redisTemplate.opsForValue().set(
                redisKey,
                "revoked",
                Duration.ofMillis(remainingTime)
        );

        System.out.println(
                "Đã Logout - JWT ID: " + jti
        );

        System.out.println(
                "TTL còn lại: " + remainingTime + " ms"
        );
    }

    // =====================================
    // KIỂM TRA TOKEN CÓ BỊ THU HỒI KHÔNG
    // =====================================

    public boolean isBlacklisted(String jti) {

        if (jti == null || jti.isBlank()) {
            return true;
        }

        String redisKey = "blacklist:" + jti;

        return Boolean.TRUE.equals(
                redisTemplate.hasKey(redisKey)
        );
    }
}
