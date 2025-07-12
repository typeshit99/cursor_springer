import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

interface User {
  username: string;
  token: string;
  refreshToken: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  refreshAccessToken: () => Promise<boolean>;
  isLoading: boolean;
  isRateLimited: boolean;
  rateLimitReset: number | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Security utility functions
const sanitizeInput = (input: string): string => {
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim();
};

const validateInput = (input: string, type: 'username' | 'email' | 'password'): boolean => {
  const patterns = {
    username: /^[a-zA-Z0-9_]{3,20}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
  };
  
  return patterns[type].test(input);
};

// Create axios instance with interceptors
const api = axios.create({
  baseURL: 'http://localhost:8080/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'
  }
});

// Request interceptor to add auth token and security headers
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // Add security headers
    config.headers['X-Client-Version'] = '1.0.0';
    config.headers['X-Request-ID'] = crypto.randomUUID();
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh and security
api.interceptors.response.use(
  (response) => {
    // Store rate limit info if available
    const rateLimitRemaining = response.headers['x-ratelimit-remaining'];
    const rateLimitReset = response.headers['x-ratelimit-reset'];
    
    if (rateLimitRemaining !== undefined) {
      localStorage.setItem('rateLimitRemaining', rateLimitRemaining);
    }
    
    if (rateLimitReset !== undefined) {
      localStorage.setItem('rateLimitReset', rateLimitReset);
    }
    
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          const response = await axios.post('http://localhost:8080/api/auth/refresh', {
            refreshToken,
          });
          
          const { token } = response.data;
          localStorage.setItem('accessToken', token);
          
          // Retry original request
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh failed, logout user
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('user');
          localStorage.removeItem('rateLimitRemaining');
          localStorage.removeItem('rateLimitReset');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }
    }

    return Promise.reject(error);
  }
);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [rateLimitReset, setRateLimitReset] = useState<number | null>(null);

  useEffect(() => {
    // Check for existing auth on app load
    const token = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    const userData = localStorage.getItem('user');
    const rateLimitResetTime = localStorage.getItem('rateLimitReset');

    if (token && refreshToken && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
      } catch (error) {
        console.error('Error parsing user data:', error);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
      }
    }

    if (rateLimitResetTime) {
      const resetTime = parseInt(rateLimitResetTime);
      if (resetTime > Date.now()) {
        setIsRateLimited(true);
        setRateLimitReset(resetTime);
      }
    }

    setIsLoading(false);
  }, []);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);
      
      // Input validation and sanitization
      if (!username || !password) {
        toast.error('Username and password are required');
        return false;
      }

      const sanitizedUsername = sanitizeInput(username);
      
      if (!validateInput(sanitizedUsername, 'username')) {
        toast.error('Username must be between 3 and 20 characters and contain only letters, numbers, and underscores');
        return false;
      }

      if (!validateInput(password, 'password')) {
        toast.error('Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character');
        return false;
      }

      // Check for suspicious patterns
      const suspiciousPatterns = ['admin', 'root', 'system', 'test', 'guest', 'user', 'demo'];
      if (suspiciousPatterns.some(pattern => sanitizedUsername.toLowerCase().includes(pattern))) {
        toast.error('Username contains restricted patterns');
        return false;
      }

      const response = await api.post('/auth/login', {
        username: sanitizedUsername,
        password,
      });

      const { token, refreshToken, username: responseUsername } = response.data;

      if (!token || !refreshToken) {
        toast.error('Invalid response from server');
        return false;
      }

      const userData: User = {
        username: responseUsername,
        token,
        refreshToken,
      };

      // Store tokens securely
      localStorage.setItem('accessToken', token);
      localStorage.setItem('refreshToken', refreshToken);
      localStorage.setItem('user', JSON.stringify(userData));

      setUser(userData);
      setIsRateLimited(false);
      setRateLimitReset(null);
      toast.success(`Welcome back, ${responseUsername}!`);
      return true;
    } catch (error: any) {
      console.error('Login error:', error);
      
      if (error.response?.status === 429) {
        const resetTime = error.response.headers['x-ratelimit-reset'];
        if (resetTime) {
          setIsRateLimited(true);
          setRateLimitReset(parseInt(resetTime));
          localStorage.setItem('rateLimitReset', resetTime);
        }
        toast.error('Too many login attempts. Please try again later.');
      } else if (error.response?.data?.message) {
        toast.error(error.response.data.message);
      } else if (error.code === 'ECONNABORTED') {
        toast.error('Request timeout. Please check your connection.');
      } else {
        toast.error('Login failed. Please try again.');
      }
      
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (username: string, email: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);
      
      // Comprehensive input validation and sanitization
      if (!username || !email || !password) {
        toast.error('All fields are required');
        return false;
      }

      const sanitizedUsername = sanitizeInput(username);
      const sanitizedEmail = sanitizeInput(email);
      
      if (!validateInput(sanitizedUsername, 'username')) {
        toast.error('Username must be between 3 and 20 characters and contain only letters, numbers, and underscores');
        return false;
      }

      if (!validateInput(sanitizedEmail, 'email')) {
        toast.error('Please enter a valid email address');
        return false;
      }

      if (!validateInput(password, 'password')) {
        toast.error('Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character');
        return false;
      }

      // Check for suspicious patterns
      const suspiciousPatterns = ['admin', 'root', 'system', 'test', 'guest', 'user', 'demo'];
      if (suspiciousPatterns.some(pattern => 
        sanitizedUsername.toLowerCase().includes(pattern) || 
        sanitizedEmail.toLowerCase().includes(pattern)
      )) {
        toast.error('Input contains restricted patterns');
        return false;
      }

      const response = await api.post('/auth/register', {
        username: sanitizedUsername,
        email: sanitizedEmail,
        password,
      });

      toast.success('Registration successful! Please log in.');
      return true;
    } catch (error: any) {
      console.error('Registration error:', error);
      
      if (error.response?.status === 429) {
        const resetTime = error.response.headers['x-ratelimit-reset'];
        if (resetTime) {
          setIsRateLimited(true);
          setRateLimitReset(parseInt(resetTime));
          localStorage.setItem('rateLimitReset', resetTime);
        }
        toast.error('Too many registration attempts. Please try again later.');
      } else if (error.response?.data?.message) {
        toast.error(error.response.data.message);
      } else if (error.code === 'ECONNABORTED') {
        toast.error('Request timeout. Please check your connection.');
      } else {
        toast.error('Registration failed. Please try again.');
      }
      
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      // Call logout endpoint to invalidate token on server
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all local storage
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      localStorage.removeItem('rateLimitRemaining');
      localStorage.removeItem('rateLimitReset');
      
      setUser(null);
      setIsRateLimited(false);
      setRateLimitReset(null);
      toast.success('Logged out successfully');
    }
  };

  const refreshAccessToken = async (): Promise<boolean> => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        return false;
      }

      const response = await axios.post('http://localhost:8080/api/auth/refresh', {
        refreshToken,
      });

      const { token } = response.data;
      localStorage.setItem('accessToken', token);

      if (user) {
        const updatedUser = { ...user, token };
        setUser(updatedUser);
        localStorage.setItem('user', JSON.stringify(updatedUser));
      }

      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
      return false;
    }
  };

  const value: AuthContextType = {
    user,
    login,
    register,
    logout,
    refreshAccessToken,
    isLoading,
    isRateLimited,
    rateLimitReset,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};