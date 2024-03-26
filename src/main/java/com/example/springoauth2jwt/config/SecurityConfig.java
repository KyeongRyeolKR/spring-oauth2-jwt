package com.example.springoauth2jwt.config;

import com.example.springoauth2jwt.service.CustomOAuth2UseService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UseService customOAuth2UseService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf disable
        http.csrf(AbstractHttpConfigurer::disable);

        // form 로그인 방식 disable
        http.formLogin(AbstractHttpConfigurer::disable);

        // HTTP Basic 인증 방식 disable
        http.httpBasic(AbstractHttpConfigurer::disable);

        // oauth2
        http.oauth2Login(
                (oauth2) -> oauth2
                        .userInfoEndpoint(
                                (userInfoEndpointConfig -> userInfoEndpointConfig
                                        .userService(customOAuth2UseService))
                        )
        );

        // 경로별 인가 작업
        http
                .authorizeHttpRequests(
                        (auth) -> auth
                                .requestMatchers("/").permitAll()
                                .anyRequest().authenticated()
                );

        // 세션 설정 : STATELESS
        http
                .sessionManagement(
                        (session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
