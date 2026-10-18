package org.example.identityservice.config;

import org.example.identityservice.security.JwtAuthenticationFilter;
import org.example.identityservice.service.TokenBlacklistService;
import org.example.identityservice.util.JwtUtil;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtUtil jwtUtil,
            TokenBlacklistService blacklistService
    ) throws Exception {

        http
                // Tắt CSRF
                .csrf(csrf -> csrf.disable())

                // Stateless
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // Chưa xác thực trả 401
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(
                                new HttpStatusEntryPoint(
                                        HttpStatus.UNAUTHORIZED
                                )
                        )
                )

                .authorizeHttpRequests(auth -> auth

                        // Register
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/auth/register"
                        ).permitAll()

                        // Login
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/auth/login"
                        ).permitAll()

                        // Refresh Token Rotation
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/auth/refresh"
                        ).permitAll()

                        // Logout yêu cầu JWT hợp lệ
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/auth/logout"
                        ).authenticated()

                        // Vô hiệu hóa endpoint test cấp JWT
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/auth/test-token"
                        ).denyAll()

                        .anyRequest().authenticated()
                )

                // Kiểm tra JWT và Redis Blacklist
                .addFilterBefore(
                        new JwtAuthenticationFilter(
                                jwtUtil,
                                blacklistService
                        ),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
