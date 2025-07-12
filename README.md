# Spring Boot JWT Authentication Application

A complete Spring Boot web application with JWT-based authentication and authorization using Spring Security.

## Features

- **User Registration**: Create new user accounts with username, password, and email
- **User Login**: Authenticate users and receive JWT tokens
- **JWT Token Authentication**: Stateless authentication using JSON Web Tokens
- **Password Encryption**: BCrypt password hashing for security
- **Protected Endpoints**: Secure API endpoints that require authentication
- **H2 Database**: In-memory database for development and testing
- **Input Validation**: Request validation using Bean Validation

## Technology Stack

- **Spring Boot 3.2.0**
- **Spring Security 6.x**
- **Spring Data JPA**
- **JWT (JSON Web Tokens)**
- **H2 Database**
- **Maven**
- **Java 17**

## Project Structure

```
src/main/java/com/example/jwtauthapp/
├── JwtAuthApplication.java          # Main application class
├── config/
│   └── SecurityConfig.java          # Spring Security configuration
├── controller/
│   ├── AuthController.java          # Authentication endpoints
│   └── TestController.java          # Test endpoints
├── dto/
│   ├── AuthResponse.java            # Authentication response DTO
│   ├── LoginRequest.java            # Login request DTO
│   └── RegisterRequest.java         # Registration request DTO
├── entity/
│   └── User.java                    # User entity
├── repository/
│   └── UserRepository.java          # User data access layer
├── security/
│   ├── CustomUserDetailsService.java # User details service
│   ├── JwtAuthenticationFilter.java # JWT authentication filter
│   └── JwtUtils.java                # JWT utility methods
└── service/
    └── UserService.java             # User business logic
```

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6 or higher

### Running the Application

1. **Clone or download the project**

2. **Navigate to the project directory**
   ```bash
   cd jwt-auth-app
   ```

3. **Build the project**
   ```bash
   mvn clean install
   ```

4. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

5. **Access the application**
   - Application will start on `http://localhost:8080`
   - H2 Database Console: `http://localhost:8080/h2-console`
     - JDBC URL: `jdbc:h2:mem:testdb`
     - Username: `sa`
     - Password: `password`

## API Endpoints

### Authentication Endpoints

#### 1. Register User
- **URL**: `POST /api/auth/register`
- **Description**: Register a new user account
- **Request Body**:
  ```json
  {
    "username": "john_doe",
    "password": "password123",
    "email": "john@example.com"
  }
  ```
- **Response**:
  ```json
  {
    "message": "User registered successfully"
  }
  ```

#### 2. Login User
- **URL**: `POST /api/auth/login`
- **Description**: Authenticate user and receive JWT token
- **Request Body**:
  ```json
  {
    "username": "john_doe",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "type": "Bearer",
    "username": "john_doe"
  }
  ```

#### 3. Test Authentication
- **URL**: `GET /api/auth/test`
- **Description**: Test if authentication endpoints are working
- **Response**: `"Authentication endpoint is working!"`

### Test Endpoints

#### 1. Public Endpoint
- **URL**: `GET /api/test/public`
- **Description**: Public endpoint (no authentication required)
- **Response**:
  ```json
  {
    "message": "This is a public endpoint - no authentication required"
  }
  ```

#### 2. Protected Endpoint
- **URL**: `GET /api/test/protected`
- **Description**: Protected endpoint (authentication required)
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Response**:
  ```json
  {
    "message": "This is a protected endpoint - authentication required",
    "username": "john_doe",
    "authorities": [{"authority": "USER"}]
  }
  ```

#### 3. User Info
- **URL**: `GET /api/test/user-info`
- **Description**: Get current user information
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Response**:
  ```json
  {
    "username": "john_doe",
    "authenticated": true,
    "authorities": [{"authority": "USER"}]
  }
  ```

## Usage Examples

### Using cURL

#### 1. Register a new user
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123",
    "email": "test@example.com"
  }'
```

#### 2. Login and get JWT token
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

#### 3. Access protected endpoint with JWT token
```bash
curl -X GET http://localhost:8080/api/test/protected \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

### Using Postman

1. **Register User**:
   - Method: `POST`
   - URL: `http://localhost:8080/api/auth/register`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "username": "testuser",
       "password": "password123",
       "email": "test@example.com"
     }
     ```

2. **Login**:
   - Method: `POST`
   - URL: `http://localhost:8080/api/auth/login`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "username": "testuser",
       "password": "password123"
     }
     ```

3. **Access Protected Endpoint**:
   - Method: `GET`
   - URL: `http://localhost:8080/api/test/protected`
   - Headers: `Authorization: Bearer YOUR_JWT_TOKEN_HERE`

## Configuration

### JWT Configuration
- **Secret Key**: Configured in `application.properties` as `jwt.secret`
- **Token Expiration**: Configured as `jwt.expiration` (default: 24 hours)

### Database Configuration
- **H2 In-Memory Database**: Used for development
- **Auto-create tables**: `spring.jpa.hibernate.ddl-auto=create-drop`
- **Show SQL**: Enabled for debugging

### Security Configuration
- **Stateless sessions**: No session management
- **CSRF disabled**: For API endpoints
- **Public endpoints**: `/api/auth/**`, `/h2-console/**`, `/api/public/**`
- **Protected endpoints**: All other endpoints require authentication

## Security Features

1. **Password Encryption**: BCrypt hashing
2. **JWT Token Validation**: Secure token verification
3. **Input Validation**: Bean Validation annotations
4. **CORS Support**: Cross-origin requests enabled
5. **Stateless Authentication**: No server-side sessions

## Error Handling

The application includes comprehensive error handling for:
- Invalid credentials
- Duplicate usernames/emails
- Invalid JWT tokens
- Validation errors
- Database errors

## Development Notes

- The application uses H2 in-memory database for simplicity
- JWT tokens expire after 24 hours by default
- All passwords are encrypted using BCrypt
- The application is configured for development with detailed logging

## Production Considerations

For production deployment, consider:
1. Using a production database (PostgreSQL, MySQL, etc.)
2. Changing the JWT secret to a secure, environment-specific value
3. Configuring proper CORS settings
4. Adding rate limiting
5. Implementing refresh tokens
6. Adding audit logging
7. Configuring HTTPS
8. Setting up proper monitoring and health checks