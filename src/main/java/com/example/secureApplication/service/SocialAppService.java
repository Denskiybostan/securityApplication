package com.example.secureApplication.service;

import com.example.secureApplication.model.Role;
import com.example.secureApplication.model.User;
import com.example.secureApplication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
@Service
public class SocialAppService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(SocialAppService.class);

    public SocialAppService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        String login = oAuth2User.getAttribute("login");
        User user = userRepository.findByUsername(oAuth2User.getAttribute("login"))
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(oAuth2User.getAttribute("login"));
                    newUser.setRoles(new HashSet<>(List.of(Role.USER)));
                    return userRepository.save(newUser);
                });
        if ("Denskiybostan".equals(login)) {
            user.getRoles().add(Role.ADMIN);
            userRepository.save(user);
            logger.info("Пользователю {} присвоена роль ADMIN", login);
        }
        logger.info("Пользователь {} успешно аутентифицирован", login);


        return new DefaultOAuth2User(
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                        .toList(),
                oAuth2User.getAttributes(), "login");
    }
    }

