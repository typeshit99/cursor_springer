package com.example.jwtauthapp.controller;

import com.example.jwtauthapp.dto.AuthResponse;
import com.example.jwtauthapp.dto.LoginRequest;
import com.example.jwtauthapp.dto.RegisterRequest;
import com.example.jwtauthapp.dto.RefreshTokenRequest;
import com.example.jwtauthapp.entity.User;
import com.example.jwtauthapp.security.JwtUtils;
import com.example.jwtauthapp.service.UserService;
import com.example.jwtauthapp.service.ValidationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private ValidationService validationService;

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        try {
            // Get client IP for rate limiting
            String clientIp = getClientIpAddress(request);
            String rateLimitKey = "login_" + clientIp;
            
            // Rate limiting check
            if (validationService.isRateLimited(rateLimitKey)) {
                logger.warn("Rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                    .header("X-RateLimit-Remaining", "0")
                    .header("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + 60000))
                    .body(new AuthResponse("Too many login attempts. Please try again later."));
            }

            // Input validation
            if (!validationService.isValidUsername(loginRequest.getUsername())) {
                logger.warn("Invalid username format attempted: {}", loginRequest.getUsername());
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid username format"));
            }

            // Sanitize inputs
            String sanitizedUsername = validationService.sanitizeInput(loginRequest.getUsername().trim());
            
            // Check for suspicious patterns
            if (containsSuspiciousPatterns(sanitizedUsername)) {
                logger.warn("Suspicious username pattern detected: {}", sanitizedUsername);
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid username format"));
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(sanitizedUsername, loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String jwt = jwtUtils.generateToken(userDetails);
            String refreshToken = jwtUtils.generateRefreshToken(userDetails);

            // Generate session ID for additional security
            String sessionId = UUID.randomUUID().toString();

            logger.info("Successful login for user: {} from IP: {}", sanitizedUsername, clientIp);

            return ResponseEntity.ok()
                .header("X-Session-ID", sessionId)
                .header("X-User-ID", userDetails.getUsername())
                .body(new AuthResponse(jwt, refreshToken, userDetails.getUsername()));
        } catch (Exception e) {
            // Log failed login attempt
            String clientIp = getClientIpAddress(request);
            logger.warn("Failed login attempt for username: {} from IP: {}", loginRequest.getUsername(), clientIp);
            return ResponseEntity.badRequest().body(new AuthResponse("Invalid username or password"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest, HttpServletRequest request) {
        try {
            // Get client IP for rate limiting
            String clientIp = getClientIpAddress(request);
            String rateLimitKey = "register_" + clientIp;
            
            // Rate limiting check
            if (validationService.isRateLimited(rateLimitKey)) {
                logger.warn("Registration rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                    .header("X-RateLimit-Remaining", "0")
                    .body(new AuthResponse("Too many registration attempts. Please try again later."));
            }

            // Comprehensive input validation
            if (!validationService.isValidUsername(registerRequest.getUsername())) {
                logger.warn("Invalid username format during registration: {}", registerRequest.getUsername());
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid username format. Username must be 3-20 characters long and contain only letters, numbers, and underscores."));
            }

            if (!validationService.isValidEmail(registerRequest.getEmail())) {
                logger.warn("Invalid email format during registration: {}", registerRequest.getEmail());
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid email format"));
            }

            if (!validationService.isValidPassword(registerRequest.getPassword())) {
                logger.warn("Weak password attempted during registration");
                return ResponseEntity.badRequest().body(new AuthResponse("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character."));
            }

            // Check for suspicious patterns
            if (containsSuspiciousPatterns(registerRequest.getUsername()) || 
                containsSuspiciousPatterns(registerRequest.getEmail())) {
                logger.warn("Suspicious patterns detected during registration from IP: {}", clientIp);
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid input format detected"));
            }

            // Check if username already exists
            if (userService.existsByUsername(registerRequest.getUsername())) {
                return ResponseEntity.badRequest().body(new AuthResponse("Username is already taken"));
            }

            // Check if email already exists
            if (userService.existsByEmail(registerRequest.getEmail())) {
                return ResponseEntity.badRequest().body(new AuthResponse("Email is already in use"));
            }

            // Create new user with sanitized inputs
            User user = new User();
            user.setUsername(validationService.sanitizeInput(registerRequest.getUsername().trim()));
            user.setPassword(registerRequest.getPassword()); // Will be hashed by service
            user.setEmail(validationService.sanitizeInput(registerRequest.getEmail().trim()));

            userService.createUser(user);

            logger.info("Successful registration for user: {} from IP: {}", registerRequest.getUsername(), clientIp);

            return ResponseEntity.ok()
                .header("X-Registration-Success", "true")
                .body(new AuthResponse("User registered successfully"));
        } catch (Exception e) {
            logger.error("Registration failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new AuthResponse("Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest request) {
        try {
            // Get client IP for rate limiting
            String clientIp = getClientIpAddress(request);
            String rateLimitKey = "refresh_" + clientIp;
            
            // Rate limiting check
            if (validationService.isRateLimited(rateLimitKey)) {
                logger.warn("Token refresh rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429).body(new AuthResponse("Too many token refresh attempts. Please try again later."));
            }

            // Validate refresh token format
            if (!validationService.isValidJwtFormat(refreshTokenRequest.getRefreshToken())) {
                logger.warn("Invalid refresh token format from IP: {}", clientIp);
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid refresh token format"));
            }

            // Extract username from refresh token
            String username = jwtUtils.extractUsername(refreshTokenRequest.getRefreshToken());
            
            // Load user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            // Validate refresh token
            if (!jwtUtils.validateRefreshToken(refreshTokenRequest.getRefreshToken(), userDetails)) {
                logger.warn("Invalid refresh token for user: {} from IP: {}", username, clientIp);
                return ResponseEntity.badRequest().body(new AuthResponse("Invalid or expired refresh token"));
            }

            // Generate new access token
            String newToken = jwtUtils.generateToken(userDetails);
            
            logger.info("Token refreshed successfully for user: {} from IP: {}", username, clientIp);

            return ResponseEntity.ok()
                .header("X-Token-Refreshed", "true")
                .body(new AuthResponse(newToken, username));
        } catch (Exception e) {
            logger.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new AuthResponse("Token refresh failed: " + e.getMessage()));
        }
    }

    @GetMapping("/test")
    public ResponseEntity<String> test(HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        logger.info("Test endpoint accessed from IP: {}", clientIp);
        return ResponseEntity.ok("Authentication endpoint is working!");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            String clientIp = getClientIpAddress(request);
            String username = getCurrentUsername();
            
            if (username != null) {
                logger.info("User logout: {} from IP: {}", username, clientIp);
            }
            
            // In a real application, you might want to blacklist the token
            // For now, we'll just return a success response
            return ResponseEntity.ok()
                .header("X-Logout-Success", "true")
                .body(new AuthResponse("Logged out successfully"));
        } catch (Exception e) {
            logger.error("Logout error: {}", e.getMessage());
            return ResponseEntity.ok().body(new AuthResponse("Logged out successfully"));
        }
    }

    // Helper methods
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    private boolean containsSuspiciousPatterns(String input) {
        if (input == null) return false;
        
        // Check for SQL injection patterns
        String[] suspiciousPatterns = {
            "admin", "root", "system", "test", "guest", "user", "demo",
            "select", "insert", "update", "delete", "drop", "create", "alter",
            "script", "javascript", "vbscript", "onload", "onerror", "onclick",
            "union", "exec", "eval", "function", "constructor", "prototype"
        };
        
        String lowerInput = input.toLowerCase();
        for (String pattern : suspiciousPatterns) {
            if (lowerInput.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }

    private String getCurrentUsername() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                return authentication.getName();
            }
        } catch (Exception e) {
            logger.debug("Could not get current username: {}", e.getMessage());
        }
        return null;
    }

    // Simple rate limiting implementation (keeping for backward compatibility)
    private final java.util.Map<String, java.util.List<Long>> loginAttempts = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_MS = 15 * 60 * 1000; // 15 minutes

    private boolean isRateLimited(String username) {
        long now = System.currentTimeMillis();
        loginAttempts.computeIfAbsent(username, k -> new java.util.ArrayList<>());
        
        // Remove old attempts outside the window
        loginAttempts.get(username).removeIf(time -> now - time > WINDOW_MS);
        
        // Check if too many attempts
        if (loginAttempts.get(username).size() >= MAX_ATTEMPTS) {
            return true;
        }
        
        return false;
    }

    private void logFailedLoginAttempt(String username) {
        long now = System.currentTimeMillis();
        loginAttempts.computeIfAbsent(username, k -> new java.util.ArrayList<>()).add(now);
    }
}