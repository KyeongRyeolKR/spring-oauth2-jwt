package com.example.springoauth2jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 컨트롤러단에서 보내주는 데이터의 CORS 설정
 */
@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 모든 경로에 적용
                .exposedHeaders("Set-Cookie") // 쿠키 반환 허용
                .allowedOrigins("http://localhost:3000"); // 프론트 URL
    }
}
