package com.example.springoauth2jwt.service;

import com.example.springoauth2jwt.dto.*;
import com.example.springoauth2jwt.entity.User;
import com.example.springoauth2jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UseService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User={}", oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if(registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if(registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        User findUser = userRepository.findByUsername(username);
        if(findUser == null) { // 첫 로그인(회원가입)
            User newUser = new User();
            newUser.setUsername(username);
            newUser.setName(oAuth2Response.getName());
            newUser.setEmail(oAuth2Response.getEmail());
            newUser.setRole("ROLE_USER");

            userRepository.save(newUser);

            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setName(oAuth2Response.getName());
            userDto.setRole("ROLE_USER");

            return new CustomOAuth2User(userDto);
        } else { // 기존 회원(바뀐 정보가 있다면 업데이트)
            findUser.setEmail(oAuth2Response.getEmail());
            findUser.setName(oAuth2Response.getName());

            UserDto userDto = new UserDto();
            userDto.setUsername(findUser.getUsername());
            userDto.setName(findUser.getName());
            userDto.setRole(findUser.getRole());

            return new CustomOAuth2User(userDto);
        }
    }
}
