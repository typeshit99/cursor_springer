package com.example.jwtauthapp.service;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.Instant;

@Service
public class ValidationService {

    // Patterns for validation
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT|JAVASCRIPT|ONLOAD|ONERROR|ONCLICK)");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<script|javascript:|vbscript:|onload|onerror|onclick|onmouseover|onfocus|onblur|onchange|onsubmit|onreset|onselect|onunload|onabort|onbeforeunload|onerror|onhashchange|onmessage|onoffline|ononline|onpagehide|onpageshow|onpopstate|onresize|onstorage|oncontextmenu|oninput|oninvalid|onsearch|onbeforecopy|onbeforecut|onbeforepaste|oncopy|oncut|onpaste|onselectstart|onmouseenter|onmouseleave|onmouseout|onmouseover|onmouseup|onmousedown|onmousemove|onkeydown|onkeypress|onkeyup|onkeydown|onkeyup|onkeypress|onfocusin|onfocusout|onblur|onfocus|onchange|oninput|oninvalid|onreset|onselect|onsubmit|onbeforeinput|onbeforeunload|onhashchange|onmessage|onoffline|ononline|onpagehide|onpageshow|onpopstate|onresize|onstorage|oncontextmenu|onsearch|onbeforecopy|onbeforecut|onbeforepaste|oncopy|oncut|onpaste|onselectstart)");
    private static final Pattern CSRF_PATTERN = Pattern.compile("(?i)(csrf|xsrf|token)");
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("(?i)(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c)");
    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile("(?i)(;|\\||&|`|\\$|\\(|\\)|\\{|\\}|\\[|\\]|<|>|\\*|\\?)");
    
    // Rate limiting storage
    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastRequestTime = new ConcurrentHashMap<>();
    
    // Security thresholds
    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final int MAX_REQUESTS_PER_HOUR = 1000;
    private static final long MIN_REQUEST_INTERVAL_MS = 100; // Minimum 100ms between requests

    /**
     * Validates username format and security
     */
    public boolean isValidUsername(String username) {
        if (!StringUtils.hasText(username)) {
            return false;
        }
        
        // Check length
        if (username.length() < 3 || username.length() > 20) {
            return false;
        }
        
        // Check pattern
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            return false;
        }
        
        // Check for SQL injection attempts
        if (containsSqlInjection(username)) {
            return false;
        }
        
        // Check for XSS attempts
        if (containsXss(username)) {
            return false;
        }
        
        // Check for path traversal attempts
        if (containsPathTraversal(username)) {
            return false;
        }
        
        // Check for command injection attempts
        if (containsCommandInjection(username)) {
            return false;
        }
        
        return true;
    }

    /**
     * Validates email format and security
     */
    public boolean isValidEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return false;
        }
        
        // Check length
        if (email.length() > 254) {
            return false;
        }
        
        // Check pattern
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return false;
        }
        
        // Check for SQL injection attempts
        if (containsSqlInjection(email)) {
            return false;
        }
        
        // Check for XSS attempts
        if (containsXss(email)) {
            return false;
        }
        
        // Check for path traversal attempts
        if (containsPathTraversal(email)) {
            return false;
        }
        
        return true;
    }

    /**
     * Validates password strength and security
     */
    public boolean isValidPassword(String password) {
        if (!StringUtils.hasText(password)) {
            return false;
        }
        
        // Check minimum length
        if (password.length() < 8) {
            return false;
        }
        
        // Check maximum length
        if (password.length() > 128) {
            return false;
        }
        
        // Check pattern (at least one lowercase, uppercase, digit, and special character)
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return false;
        }
        
        // Check for common weak passwords
        if (isCommonWeakPassword(password)) {
            return false;
        }
        
        // Check for sequential characters
        if (containsSequentialChars(password)) {
            return false;
        }
        
        // Check for repeated characters
        if (containsRepeatedChars(password)) {
            return false;
        }
        
        return true;
    }

    /**
     * Sanitizes input to prevent XSS and injection attacks
     */
    public String sanitizeInput(String input) {
        if (!StringUtils.hasText(input)) {
            return input;
        }
        
        // Remove or escape potentially dangerous characters
        return input
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("&", "&amp;")
                .replace("(", "&#40;")
                .replace(")", "&#41;")
                .replace(";", "&#59;")
                .replace(":", "&#58;")
                .replace("=", "&#61;")
                .replace("+", "&#43;")
                .replace("-", "&#45;")
                .replace("`", "&#96;")
                .replace("~", "&#126;")
                .replace("!", "&#33;")
                .replace("@", "&#64;")
                .replace("#", "&#35;")
                .replace("$", "&#36;")
                .replace("%", "&#37;")
                .replace("^", "&#94;")
                .replace("*", "&#42;")
                .replace("|", "&#124;")
                .replace("\\", "&#92;")
                .replace("/", "&#47;")
                .replace("?", "&#63;")
                .replace("[", "&#91;")
                .replace("]", "&#93;")
                .replace("{", "&#123;")
                .replace("}", "&#125;");
    }

    /**
     * Validates and sanitizes JSON input
     */
    public String sanitizeJsonInput(String jsonInput) {
        if (!StringUtils.hasText(jsonInput)) {
            return jsonInput;
        }
        
        // Basic JSON structure validation
        if (!jsonInput.trim().startsWith("{") && !jsonInput.trim().startsWith("[")) {
            throw new IllegalArgumentException("Invalid JSON format");
        }
        
        // Check for potential JSON injection
        if (containsJsonInjection(jsonInput)) {
            throw new IllegalArgumentException("Potentially malicious JSON content detected");
        }
        
        return sanitizeInput(jsonInput);
    }

    /**
     * Validates request rate limiting
     */
    public boolean isRateLimited(String identifier) {
        long currentTime = System.currentTimeMillis();
        
        // Check minimum interval between requests
        Long lastTime = lastRequestTime.get(identifier);
        if (lastTime != null && currentTime - lastTime < MIN_REQUEST_INTERVAL_MS) {
            return true;
        }
        
        // Update last request time
        lastRequestTime.put(identifier, currentTime);
        
        // Get or create request counter
        AtomicInteger counter = requestCounts.computeIfAbsent(identifier, k -> new AtomicInteger(0));
        
        // Increment counter
        int currentCount = counter.incrementAndGet();
        
        // Check per-minute limit
        if (currentCount > MAX_REQUESTS_PER_MINUTE) {
            return true;
        }
        
        // Reset counter every minute
        if (currentTime % 60000 < 1000) {
            counter.set(0);
        }
        
        return false;
    }

    /**
     * Validates CSRF token
     */
    public boolean isValidCsrfToken(String token, String sessionId) {
        if (!StringUtils.hasText(token) || !StringUtils.hasText(sessionId)) {
            return false;
        }
        
        try {
            // Generate expected token based on session ID
            String expectedToken = generateCsrfToken(sessionId);
            return token.equals(expectedToken);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generates CSRF token
     */
    public String generateCsrfToken(String sessionId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String data = sessionId + "CSRF_SECRET_" + Instant.now().getEpochSecond();
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate CSRF token", e);
        }
    }

    /**
     * Checks if input contains SQL injection attempts
     */
    private boolean containsSqlInjection(String input) {
        return SQL_INJECTION_PATTERN.matcher(input).find();
    }

    /**
     * Checks if input contains XSS attempts
     */
    private boolean containsXss(String input) {
        return XSS_PATTERN.matcher(input).find();
    }

    /**
     * Checks if input contains path traversal attempts
     */
    private boolean containsPathTraversal(String input) {
        return PATH_TRAVERSAL_PATTERN.matcher(input).find();
    }

    /**
     * Checks if input contains command injection attempts
     */
    private boolean containsCommandInjection(String input) {
        return COMMAND_INJECTION_PATTERN.matcher(input).find();
    }

    /**
     * Checks if input contains JSON injection attempts
     */
    private boolean containsJsonInjection(String input) {
        return input.contains("__proto__") || 
               input.contains("constructor") || 
               input.contains("prototype") ||
               input.contains("eval(") ||
               input.contains("Function(");
    }

    /**
     * Checks if password is a common weak password
     */
    private boolean isCommonWeakPassword(String password) {
        String[] weakPasswords = {
            "password", "123456", "123456789", "qwerty", "abc123", "password123",
            "admin", "letmein", "welcome", "monkey", "dragon", "master", "hello",
            "freedom", "whatever", "qwerty123", "trustno1", "jordan", "harley",
            "ranger", "iwantu", "jennifer", "hunter", "buster", "soccer", "baseball",
            "tequiero", "princess", "mercedes", "dolphin", "cooper", "internet",
            "service", "canada", "hello", "robert", "tiger", "russia", "thomas",
            "jordan", "michelle", "charles", "andrew", "matthew", "anthony", "mark",
            "donald", "steven", "paul", "aaron", "kenneth", "joshua", "kevin",
            "brian", "george", "timothy", "ronald", "jason", "edward", "jeffrey",
            "ryan", "jacob", "gary", "nicholas", "eric", "jonathan", "stephen",
            "larry", "justin", "scott", "brandon", "benjamin", "samuel", "frank",
            "gregory", "raymond", "alexander", "patrick", "jack", "dennis", "jerry",
            "tyler", "aaron", "jose", "adam", "nathan", "henry", "douglas", "zachary",
            "peter", "kyle", "walter", "ethan", "jeremy", "harold", "seth", "christian",
            "mason", "austin", "jack", "noah", "dylan", "benjamin", "logan", "alexander",
            "sebastian", "elijah", "james", "oliver", "henry", "michael", "daniel",
            "jacob", "logan", "jackson", "sebastian", "jack", "owen", "samuel",
            "aiden", "julian", "matthew", "elijah", "leo", "theodore", "hudson",
            "christian", "andrew", "thomas", "joshua", "nathan", "adrian", "asher",
            "isaac", "leo", "christopher", "andrew", "theodore", "caleb", "ryan",
            "asher", "nathan", "christopher", "sean", "eli", "baseball", "dolphin",
            "eagle", "green", "hammer", "hello", "internet", "jordan", "love",
            "maggie", "mike", "mustang", "password", "pussy", "qwerty", "secret",
            "shadow", "steelers", "sunshine", "superman", "trustno1", "welcome",
            "whatever", "yamaha", "zombie", "123456", "123456789", "12345678",
            "1234567", "1234567890", "111111", "000000", "abc123", "qwerty123",
            "1q2w3e4r", "1qaz2wsx", "qazwsx", "password123", "admin123", "letmein123"
        };
        
        String lowerPassword = password.toLowerCase();
        for (String weakPassword : weakPasswords) {
            if (lowerPassword.equals(weakPassword)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if password contains sequential characters
     */
    private boolean containsSequentialChars(String password) {
        String lowerPassword = password.toLowerCase();
        String sequences = "abcdefghijklmnopqrstuvwxyz0123456789";
        
        for (int i = 0; i < sequences.length() - 2; i++) {
            String seq = sequences.substring(i, i + 3);
            if (lowerPassword.contains(seq)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if password contains repeated characters
     */
    private boolean containsRepeatedChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) && 
                password.charAt(i) == password.charAt(i + 2)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates JWT token format
     */
    public boolean isValidJwtFormat(String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }
        
        // JWT tokens should have 3 parts separated by dots
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        
        // Each part should be base64 encoded
        for (String part : parts) {
            if (!part.matches("^[A-Za-z0-9+/]*={0,2}$")) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * Validates file upload security
     */
    public boolean isValidFileUpload(String fileName, String contentType, long fileSize) {
        // Check file size (max 10MB)
        if (fileSize > 10 * 1024 * 1024) {
            return false;
        }
        
        // Check file extension
        String[] allowedExtensions = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"};
        String lowerFileName = fileName.toLowerCase();
        boolean hasValidExtension = false;
        
        for (String ext : allowedExtensions) {
            if (lowerFileName.endsWith(ext)) {
                hasValidExtension = true;
                break;
            }
        }
        
        if (!hasValidExtension) {
            return false;
        }
        
        // Check content type
        String[] allowedTypes = {"image/", "application/pdf", "text/", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"};
        boolean hasValidType = false;
        
        for (String type : allowedTypes) {
            if (contentType.startsWith(type)) {
                hasValidType = true;
                break;
            }
        }
        
        return hasValidType;
    }
}