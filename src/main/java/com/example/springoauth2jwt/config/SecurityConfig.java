package com.example.springoauth2jwt.config;

import com.example.springoauth2jwt.jwt.JwtFilter;
import com.example.springoauth2jwt.oauth2.CustomSuccessHandler;
import com.example.springoauth2jwt.service.CustomOAuth2UseService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UseService customOAuth2UseService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 스프링 시큐리티의 CORS 설정
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        // 프론트엔드가 백엔드에게 데이터를 주는 경우 설정
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 프론트 URL
                        configuration.setAllowedMethods(Collections.singletonList("*")); // 모든 메서드 허용
                        configuration.setAllowCredentials(true); // credential 값 허용
                        configuration.setAllowedHeaders(Collections.singletonList("*")); // 헤더 값 허용
                        configuration.setMaxAge(3600L);

                        // 백엔드가 프론트엔드에게 데이터를 주는 경우 설정
                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie")); // 쿠키 반환 허용
                        configuration.setExposedHeaders(Collections.singletonList("Authorization")); // Authorization 헤더 반환 허용

                        return configuration;
                    }
                }));

        // csrf disable
        http.csrf(AbstractHttpConfigurer::disable);

        // form 로그인 방식 disable
        http.formLogin(AbstractHttpConfigurer::disable);

        // HTTP Basic 인증 방식 disable
        http.httpBasic(AbstractHttpConfigurer::disable);

        // JwtFilter 등록
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // oauth2
        http.oauth2Login(
                (oauth2) -> oauth2
                        .userInfoEndpoint(
                                (userInfoEndpointConfig -> userInfoEndpointConfig
                                        .userService(customOAuth2UseService))
                        )
                        .successHandler(customSuccessHandler) // 로그인 성공 핸들러 등록
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
