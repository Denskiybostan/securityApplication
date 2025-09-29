package com.example.secureApplication.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
@RestController
public class UserController {
    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("name", principal.getAttribute("name"));
        profile.put("login", principal.getAttribute("login"));
        profile.put("id", principal.getAttribute("id"));
        profile.put("email", principal.getAttribute("email"));
        return profile;
    }
}
