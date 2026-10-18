package org.example.identityservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.example.identityservice.service.TokenBlacklistService;
import org.example.identityservice.util.JwtUtil;

import org.springframework.http.HttpHeaders;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService blacklistService;

    public JwtAuthenticationFilter(
            JwtUtil jwtUtil,
            TokenBlacklistService blacklistService
    ) {
        this.jwtUtil = jwtUtil;
        this.blacklistService = blacklistService;
    }

    // Không bắt buộc JWT cho Login, Register, Refresh
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.equals("/api/auth/login")
                || path.equals("/api/auth/register")
                || path.equals("/api/auth/refresh");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authorization =
                request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization != null
                && authorization.startsWith("Bearer ")) {

            String token = authorization.substring(7).trim();

            try {

                // 1. Xác minh JWT
                Claims claims = jwtUtil.extractClaims(token);

                // 2. Lấy JTI
                String jti = claims.getId();

                // 3. Kiểm tra Blacklist
                if (blacklistService.isBlacklisted(jti)) {

                    throw new JwtException(
                            "Token đã bị thu hồi hoặc thiếu JTI"
                    );
                }

                // 4. Lấy thông tin User
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                if (username == null || username.isBlank()
                        || role == null || role.isBlank()) {

                    throw new JwtException(
                            "JWT thiếu username hoặc role"
                    );
                }

                // 5. Chuyển role sang Spring Security Authority
                String authority = role.startsWith("ROLE_")
                        ? role
                        : "ROLE_" + role;

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                List.of(
                                        new SimpleGrantedAuthority(authority)
                                )
                        );

                // 6. Đưa Authentication vào SecurityContext
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);

            } catch (JwtException | IllegalArgumentException e) {

                SecurityContextHolder.clearContext();

                response.setStatus(
                        HttpServletResponse.SC_UNAUTHORIZED
                );

                response.setContentType(
                        "application/json;charset=UTF-8"
                );

                response.getWriter().write(
                        "{\"message\":\"Invalid or revoked token\"}"
                );

                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
