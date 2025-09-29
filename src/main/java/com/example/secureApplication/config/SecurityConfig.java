package com.example.secureApplication.config;

import com.example.secureApplication.filter.JwtAuthenticationFilter;
import com.example.secureApplication.filter.LoggingFilter;
import com.example.secureApplication.service.OurUserDetailedService;
import com.example.secureApplication.service.SocialAppService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final OurUserDetailedService ourUserDetailedService;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final LoggingFilter loggingFilter;
    private final SocialAppService socialAppService;

    public SecurityConfig(OurUserDetailedService ourUserDetailedService, JwtAuthenticationFilter jwtAuthenticationFilter, LoggingFilter loggingFilter, SocialAppService socialAppService) {
        this.ourUserDetailedService = ourUserDetailedService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.loggingFilter = loggingFilter;
        this.socialAppService = socialAppService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/", "/login", "/error", "/webjars/**").permitAll()
                        .requestMatchers("/h2-console/*").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Вы не авторизованы (401 Unauthorized)\"}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Доступ запрещён (403 Forbidden)\"}");
                        })
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/")
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(socialAppService))
                        .defaultSuccessUrl("/user", true)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return ourUserDetailedService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(ourUserDetailedService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
        // Установка сервиса для загрузки пользовательских данных
        // Установка PasswordEncoder для проверки паролей
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {

            request.getSession().invalidate();
            response.sendRedirect("/");
        };
    }

}
