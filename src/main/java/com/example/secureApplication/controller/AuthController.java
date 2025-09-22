package com.example.secureApplication.controller;

import com.example.secureApplication.JWT.JWTUtils;
import com.example.secureApplication.model.User;
import com.example.secureApplication.service.OurUserDetailedService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JWTUtils jwtUtils;
    private final OurUserDetailedService ourUserDetailedService;

    public AuthController(AuthenticationManager authenticationManager, JWTUtils jwtUtils, OurUserDetailedService ourUserDetailedService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.ourUserDetailedService = ourUserDetailedService;
    }
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User saved = ourUserDetailedService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable long id) {
        ourUserDetailedService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
    @PutMapping("/{id}")
    public ResponseEntity<User> updateDepartment(@PathVariable long id, @RequestBody User userUpdate) {
        User updateUser  = ourUserDetailedService.updateUser(id, userUpdate);
        return ResponseEntity.ok(updateUser);
    }
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> loginRequest) {
        String username = loginRequest.get("username");
        String password = loginRequest.get("password");

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String jwt = jwtUtils.generateToken(userDetails);
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", jwt);
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String username = jwtUtils.extractUsername(refreshToken);
        UserDetails userDetails = ourUserDetailedService.loadUserByUsername(username);

        if (jwtUtils.isTokenValid(refreshToken, userDetails)) {
            String newToken = jwtUtils.generateToken(userDetails);

            Map<String, String> response = new HashMap<>();
            response.put("accessToken", newToken);
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }


}
