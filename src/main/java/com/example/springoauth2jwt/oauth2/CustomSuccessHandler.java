package com.example.springoauth2jwt.oauth2;

import com.example.springoauth2jwt.dto.CustomOAuth2User;
import com.example.springoauth2jwt.jwt.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    /**
     * 응답 데이터(JWT)를 쿠키에 담아서 반환
     * -> 백엔드가 로그인에 대한 모든 책임을 지기 위해 프론트에서는 하이퍼링크로 백엔드 API를 호출하는데,
     *    최종 응답된 값을 프론트에서 받는게 굉장히 까다로우므로 쿠키 방식으로 값을 확인할 수 있게 한다!
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        String username = customOAuth2User.getUsername();
        String role = authentication.getAuthorities().iterator().next().getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*60L);

        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:3000/");
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60*60*60);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
//        cookie.setSecure(true); // HTTPS에서만 쿠키 사용 허용 옵션 -> 개발 환경은 HTTP 이므로 주석 처리

        return cookie;
    }
}
