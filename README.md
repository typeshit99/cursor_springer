# � Secure JWT Authentication System

A comprehensive, bulletproof Spring Boot backend with a beautiful React frontend featuring enterprise-grade security measures.

## 🚀 Features

### � Security Features

#### Backend Security
- **JWT Authentication**: Secure token-based authentication with automatic refresh
- **Rate Limiting**: Protection against brute force attacks (60 requests/minute per IP)
- **Input Validation**: Comprehensive validation and sanitization of all inputs
- **XSS Protection**: Cross-site scripting attack prevention
- **CSRF Protection**: Cross-site request forgery protection
- **SQL Injection Protection**: Pattern-based detection and prevention
- **Path Traversal Protection**: Prevention of directory traversal attacks
- **Command Injection Protection**: Shell command injection prevention
- **Password Strength Validation**: Enforces strong password requirements
- **Suspicious Pattern Detection**: Blocks common attack patterns
- **Security Headers**: Comprehensive HTTP security headers
- **CORS Configuration**: Strict cross-origin resource sharing policies
- **Session Management**: Stateless JWT-based sessions
- **Logging & Monitoring**: Comprehensive security event logging

#### Frontend Security
- **Input Sanitization**: Client-side input cleaning and validation
- **Token Management**: Secure token storage and automatic refresh
- **Rate Limiting Detection**: Real-time rate limit status display
- **Security Indicators**: Visual security status and strength indicators
- **Protected Routes**: Route-based authentication guards
- **Error Handling**: Secure error messages without information leakage
- **XSS Prevention**: Content Security Policy compliance
- **Secure Storage**: Local storage with automatic cleanup

### 🎨 UI/UX Features

#### Beautiful Design
- **Modern Material-UI**: Clean, professional interface
- **Smooth Animations**: Framer Motion powered transitions
- **Responsive Design**: Mobile-first responsive layout
- **Dark/Light Theme**: Adaptive theme system
- **Loading States**: Elegant loading indicators
- **Toast Notifications**: User-friendly feedback system

#### User Experience
- **Password Strength Indicator**: Real-time password strength feedback
- **Progress Steppers**: Guided registration process
- **Security Dashboard**: Comprehensive security overview
- **Session Timer**: Real-time session duration display
- **Token Viewer**: Secure JWT token inspection
- **Mobile Menu**: Responsive mobile navigation

## �️ Technology Stack

### Backend
- **Spring Boot 3.x**: Modern Java framework
- **Spring Security**: Enterprise security framework
- **JWT (JSON Web Tokens)**: Stateless authentication
- **H2 Database**: In-memory database for development
- **BCrypt**: Secure password hashing (12 rounds)
- **Maven**: Dependency management

### Frontend
- **React 19**: Modern React with hooks
- **TypeScript**: Type-safe JavaScript
- **Material-UI (MUI)**: Professional UI components
- **Framer Motion**: Smooth animations
- **React Hook Form**: Form management with validation
- **Yup**: Schema validation
- **Axios**: HTTP client with interceptors
- **React Router**: Client-side routing

## � Prerequisites

- **Java 17+**: Required for Spring Boot 3.x
- **Node.js 16+**: Required for React development
- **npm 8+**: Package manager
- **Maven 3.6+**: Java build tool

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd secure-jwt-auth-system
```

### 2. Install Dependencies
```bash
# Install all dependencies (backend + frontend)
npm run install-all

# Or install separately:
npm install                    # Root dependencies
cd frontend && npm install     # Frontend dependencies
```

### 3. Start the Application

#### Development Mode (Both Backend and Frontend)
```bash
npm run dev
```

#### Start Backend Only
```bash
npm run start-backend
```

#### Start Frontend Only
```bash
npm run start-frontend
```

### 4. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **H2 Database Console**: http://localhost:8080/h2-console

## 🔐 Demo Account

For testing purposes, you can use the demo account:
- **Username**: `demo_user`
- **Password**: `DemoPass123!`

## 📁 Project Structure

```
secure-jwt-auth-system/
├── src/                          # Backend source code
│   └── main/java/com/example/jwtauthapp/
│       ├── config/               # Security configuration
│       ├── controller/           # REST API controllers
│       ├── dto/                  # Data transfer objects
│       ├── entity/               # Database entities
│       ├── repository/           # Data access layer
│       ├── security/             # JWT and security components
│       └── service/              # Business logic
├── frontend/                     # React frontend
│   ├── src/
│   │   ├── components/           # Reusable UI components
│   │   ├── contexts/             # React contexts
│   │   ├── pages/                # Page components
│   │   └── App.tsx              # Main application component
│   └── package.json
├── pom.xml                      # Maven configuration
└── package.json                 # Root package configuration
```

## 🔧 Configuration

### Backend Configuration (`application.properties`)

```properties
# Server Configuration
server.port=8080

# Database Configuration
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password

# JWT Configuration
jwt.secret=your-super-secure-jwt-secret-key-256-bits-minimum
jwt.expiration=3600000          # 1 hour
jwt.refresh-expiration=604800000 # 7 days

# Security Configuration
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true
```

### Frontend Configuration

The frontend automatically connects to `http://localhost:8080/api` for the backend API.

## �️ Security Measures

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)
- No sequential characters (abc, 123, etc.)
- No repeated characters (aaa, 111, etc.)
- No common weak passwords

### Username Requirements
- 3-20 characters
- Letters, numbers, and underscores only
- No restricted patterns (admin, root, system, etc.)

### Rate Limiting
- **Login**: 60 requests per minute per IP
- **Registration**: 60 requests per minute per IP
- **Token Refresh**: 60 requests per minute per IP
- **Minimum Interval**: 100ms between requests

### Security Headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME type sniffing protection
- **X-XSS-Protection**: XSS protection
- **Referrer-Policy**: Referrer information control
- **Permissions-Policy**: Feature policy control

## 🧪 Testing

### Backend Tests
```bash
mvn test
```

### Frontend Tests
```bash
cd frontend
npm test
```

### Run All Tests
```bash
npm run test
```

## 🚀 Production Deployment

### Backend Deployment
1. **Build the JAR**:
   ```bash
   mvn clean package
   ```

2. **Run the JAR**:
   ```bash
   java -jar target/jwt-auth-app-1.0.0.jar
   ```

### Frontend Deployment
1. **Build for Production**:
   ```bash
   cd frontend
   npm run build
   ```

2. **Deploy the `build` folder** to your web server

### Environment Variables for Production
```bash
# JWT Secret (use a strong, random secret)
JWT_SECRET=your-production-secret-key-256-bits-minimum

# Database URL
DATABASE_URL=jdbc:postgresql://localhost:5432/authdb

# Server Port
SERVER_PORT=8080
```

## 🔍 API Endpoints

### Authentication Endpoints
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - User logout
- `GET /api/auth/test` - Test endpoint

### Protected Endpoints
- `GET /api/test/user-info` - Get user information (requires authentication)

## �️ Development

### Adding New Features
1. **Backend**: Add controllers, services, and entities in the appropriate packages
2. **Frontend**: Add components in `frontend/src/components` and pages in `frontend/src/pages`
3. **Security**: Ensure all new endpoints are properly secured and validated

### Code Style
- **Backend**: Follow Java conventions and Spring Boot best practices
- **Frontend**: Use TypeScript, follow React hooks patterns, and maintain consistent styling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](../../issues) page for existing solutions
2. Create a new issue with detailed information
3. Include your environment details and error logs

## 🔐 Security Considerations

### For Production Use
1. **Change Default Secrets**: Update JWT secret and database passwords
2. **Use HTTPS**: Always use HTTPS in production
3. **Database Security**: Use a production-grade database with proper security
4. **Environment Variables**: Store sensitive configuration in environment variables
5. **Regular Updates**: Keep dependencies updated for security patches
6. **Monitoring**: Implement proper logging and monitoring
7. **Backup Strategy**: Implement regular database backups

### Security Best Practices
- Never commit secrets to version control
- Use strong, unique passwords
- Implement proper error handling
- Regular security audits
- Keep dependencies updated
- Monitor for suspicious activities

---

**⚠️ Disclaimer**: This is a demonstration project. For production use, ensure all security measures are properly configured and tested in your specific environment.