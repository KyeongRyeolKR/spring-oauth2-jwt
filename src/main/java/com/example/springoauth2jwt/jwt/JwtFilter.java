package com.example.springoauth2jwt.jwt;

import com.example.springoauth2jwt.dto.CustomOAuth2User;
import com.example.springoauth2jwt.dto.UserDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("Authorization")) {
                authorization = cookie.getValue();
            }
        }

        // Authorization 헤더 검증
        if(authorization == null) {
            log.info("token null");
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰
        String token = authorization;

        // 토큰 만료 검증
        if(jwtUtil.isExpired(token)) {
            log.info("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰에서 사용자 정보 추출
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // DTO 생성
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setRole(role);

        // OAuth2User 객체 생성
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDto);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
