package com.example.jwtauthapp.config;

import com.example.jwtauthapp.security.CustomUserDetailsService;
import com.example.jwtauthapp.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Increased strength
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins only
        configuration.setAllowedOriginPatterns(List.of(
            "http://localhost:3000", 
            "https://localhost:3000",
            "http://127.0.0.1:3000",
            "https://127.0.0.1:3000"
        ));
        
        // Allow specific methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // Allow specific headers
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type", 
            "X-Requested-With", 
            "Accept", 
            "Origin", 
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-Session-ID",
            "X-User-ID",
            "X-CSRF-Token"
        ));
        
        // Expose headers to client
        configuration.setExposedHeaders(Arrays.asList(
            "X-Session-ID",
            "X-User-ID", 
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Token-Refreshed",
            "X-Registration-Success",
            "X-Logout-Success"
        ));
        
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // CSRF protection (disabled for API endpoints but we handle it manually)
            .csrf(csrf -> csrf.disable())
            
            // Session management
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Authorization rules
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/h2-console/**").permitAll()
                    .requestMatchers("/api/public/**").permitAll()
                    .requestMatchers("/error").permitAll()
                    .requestMatchers("/actuator/health").permitAll()
                    .anyRequest().authenticated()
            )
            
            // Comprehensive security headers
            .headers(headers -> headers
                // Frame options (for H2 console)
                .frameOptions().disable()
                
                // Content type options
                .contentTypeOptions().and()
                
                // HTTP Strict Transport Security (HSTS)
                .httpStrictTransportSecurity(hstsConfig -> 
                    hstsConfig
                        .maxAgeInSeconds(31536000)
                        .includeSubdomains(true)
                        .preload(true)
                )
                
                // XSS Protection
                .xssProtection(xssConfig -> 
                    xssConfig.enable(true).block(true)
                )
                
                // Content Security Policy (CSP)
                .contentSecurityPolicy(cspConfig -> 
                    cspConfig.policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
                        "font-src 'self' https://fonts.gstatic.com; " +
                        "img-src 'self' data: https:; " +
                        "connect-src 'self' ws: wss:; " +
                        "frame-ancestors 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self'; " +
                        "upgrade-insecure-requests"
                    )
                )
                
                // Referrer Policy
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                
                // Permissions Policy
                .addHeaderWriter((request, response) -> {
                    response.setHeader("Permissions-Policy", 
                        "geolocation=(), " +
                        "microphone=(), " +
                        "camera=(), " +
                        "payment=(), " +
                        "usb=(), " +
                        "magnetometer=(), " +
                        "gyroscope=(), " +
                        "accelerometer=(), " +
                        "ambient-light-sensor=(), " +
                        "autoplay=(), " +
                        "encrypted-media=(), " +
                        "picture-in-picture=(), " +
                        "publickey-credentials-get=(), " +
                        "screen-wake-lock=(), " +
                        "sync-xhr=(), " +
                        "web-share=()"
                    );
                })
                
                // Additional security headers
                .addHeaderWriter((request, response) -> {
                    // Cache control for sensitive endpoints
                    if (request.getRequestURI().startsWith("/api/auth/")) {
                        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                        response.setHeader("Pragma", "no-cache");
                        response.setHeader("Expires", "0");
                    }
                    
                    // X-Content-Type-Options
                    response.setHeader("X-Content-Type-Options", "nosniff");
                    
                    // X-Download-Options
                    response.setHeader("X-Download-Options", "noopen");
                    
                    // X-Permitted-Cross-Domain-Policies
                    response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
                    
                    // X-DNS-Prefetch-Control
                    response.setHeader("X-DNS-Prefetch-Control", "off");
                    
                    // X-Frame-Options (additional protection)
                    response.setHeader("X-Frame-Options", "DENY");
                    
                    // Clear-Site-Data (for logout)
                    if (request.getRequestURI().equals("/api/auth/logout")) {
                        response.setHeader("Clear-Site-Data", "\"cache\", \"cookies\", \"storage\"");
                    }
                })
            )
            
            // Authentication provider
            .authenticationProvider(authenticationProvider())
            
            // JWT filter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}