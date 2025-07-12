import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Link,
  InputAdornment,
  IconButton,
  Alert,
  CircularProgress,
  Paper,
  Chip,
  Divider,
  Fade,
  Zoom,
  Slide,
} from '@mui/material';
import { useNavigate, Link as RouterLink } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Visibility, 
  VisibilityOff, 
  LockOutlined, 
  EmailOutlined,
  PersonOutlined,
  SecurityOutlined,
  ShieldOutlined,
  CheckCircleOutline,
  ErrorOutline,
  WarningAmber,
  TimerOutlined
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const schema = yup.object({
  username: yup
    .string()
    .required('Username is required')
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
    .test('no-suspicious-patterns', 'Username contains restricted patterns', (value) => {
      if (!value) return true;
      const suspiciousPatterns = ['admin', 'root', 'system', 'test', 'guest', 'user', 'demo'];
      return !suspiciousPatterns.some(pattern => value.toLowerCase().includes(pattern));
    }),
  password: yup
    .string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters')
    .matches(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
      'Password must contain uppercase, lowercase, number, and special character'
    ),
}).required();

type FormData = yup.InferType<typeof schema>;

const Login: React.FC = () => {
  const { login, isLoading, isRateLimited, rateLimitReset } = useAuth();
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [securityLevel, setSecurityLevel] = useState<'low' | 'medium' | 'high'>('low');
  const [timeRemaining, setTimeRemaining] = useState<number>(0);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    setValue,
    watch,
  } = useForm<FormData>({
    resolver: yupResolver(schema),
    mode: 'onChange',
  });

  const watchedPassword = watch('password', '');

  // Calculate security level based on password strength
  useEffect(() => {
    if (!watchedPassword) {
      setSecurityLevel('low');
      return;
    }

    let score = 0;
    if (watchedPassword.length >= 8) score++;
    if (/[a-z]/.test(watchedPassword)) score++;
    if (/[A-Z]/.test(watchedPassword)) score++;
    if (/\d/.test(watchedPassword)) score++;
    if (/[@$!%*?&]/.test(watchedPassword)) score++;
    if (watchedPassword.length >= 12) score++;

    if (score >= 5) setSecurityLevel('high');
    else if (score >= 3) setSecurityLevel('medium');
    else setSecurityLevel('low');
  }, [watchedPassword]);

  // Countdown timer for rate limiting
  useEffect(() => {
    if (rateLimitReset && isRateLimited) {
      const interval = setInterval(() => {
        const remaining = Math.max(0, Math.ceil((rateLimitReset - Date.now()) / 1000));
        setTimeRemaining(remaining);
        if (remaining === 0) {
          setTimeRemaining(0);
        }
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [rateLimitReset, isRateLimited]);

  const onSubmit = async (data: FormData) => {
    setError(null);
    const success = await login(data.username, data.password);
    if (success) {
      navigate('/dashboard');
    }
  };

  const handleShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const handleDemoLogin = async () => {
    setValue('username', 'demo_user');
    setValue('password', 'DemoPass123!');
    setError(null);
    const success = await login('demo_user', 'DemoPass123!');
    if (success) {
      navigate('/dashboard');
    }
  };

  const getSecurityColor = () => {
    switch (securityLevel) {
      case 'high': return '#10b981';
      case 'medium': return '#f59e0b';
      case 'low': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getSecurityText = () => {
    switch (securityLevel) {
      case 'high': return 'Strong Password';
      case 'medium': return 'Medium Strength';
      case 'low': return 'Weak Password';
      default: return 'Enter Password';
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: 2,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Animated background elements */}
      <motion.div
        style={{
          position: 'absolute',
          top: '10%',
          left: '10%',
          width: 100,
          height: 100,
          borderRadius: '50%',
          background: 'rgba(255, 255, 255, 0.1)',
        }}
        animate={{
          y: [0, -20, 0],
          scale: [1, 1.1, 1],
        }}
        transition={{
          duration: 4,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      <motion.div
        style={{
          position: 'absolute',
          bottom: '20%',
          right: '15%',
          width: 150,
          height: 150,
          borderRadius: '50%',
          background: 'rgba(255, 255, 255, 0.05)',
        }}
        animate={{
          y: [0, 30, 0],
          scale: [1, 0.9, 1],
        }}
        transition={{
          duration: 6,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        style={{ width: '100%', maxWidth: 450 }}
      >
        <Card
          sx={{
            borderRadius: 3,
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.1)',
            overflow: 'visible',
            background: 'rgba(255, 255, 255, 0.95)',
            backdropFilter: 'blur(10px)',
          }}
        >
          <CardContent sx={{ p: 4 }}>
            {/* Header */}
            <Box textAlign="center" mb={3}>
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
              >
                <Box
                  sx={{
                    width: 70,
                    height: 70,
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 20px',
                    boxShadow: '0 8px 16px rgba(102, 126, 234, 0.3)',
                  }}
                >
                  <SecurityOutlined sx={{ color: 'white', fontSize: 32 }} />
                </Box>
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700, color: '#1e293b' }}>
                  Welcome Back
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Sign in to your secure account
                </Typography>
              </motion.div>
            </Box>

            {/* Rate limiting alert */}
            <AnimatePresence>
              {isRateLimited && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <Alert 
                    severity="warning" 
                    sx={{ mb: 3 }}
                    icon={<TimerOutlined />}
                  >
                    <Typography variant="body2" fontWeight={600}>
                      Rate limit exceeded
                    </Typography>
                    <Typography variant="body2">
                      Please wait {formatTime(timeRemaining)} before trying again
                    </Typography>
                  </Alert>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Error alert */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                >
                  <Alert severity="error" sx={{ mb: 3 }} icon={<ErrorOutline />}>
                    {error}
                  </Alert>
                </motion.div>
              )}
            </AnimatePresence>

            <form onSubmit={handleSubmit(onSubmit)}>
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 }}
              >
                <TextField
                  {...register('username')}
                  fullWidth
                  label="Username"
                  variant="outlined"
                  margin="normal"
                  error={!!errors.username}
                  helperText={errors.username?.message}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <PersonOutlined color="action" />
                      </InputAdornment>
                    ),
                  }}
                  sx={{ mb: 2 }}
                  disabled={isRateLimited}
                />
              </motion.div>

              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.5 }}
              >
                <TextField
                  {...register('password')}
                  fullWidth
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  variant="outlined"
                  margin="normal"
                  error={!!errors.password}
                  helperText={errors.password?.message}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <LockOutlined color="action" />
                      </InputAdornment>
                    ),
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          aria-label="toggle password visibility"
                          onClick={handleShowPassword}
                          edge="end"
                        >
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                  sx={{ mb: 1 }}
                  disabled={isRateLimited}
                />
              </motion.div>

              {/* Password strength indicator */}
              {watchedPassword && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ShieldOutlined sx={{ color: getSecurityColor(), fontSize: 16 }} />
                    <Typography variant="body2" color={getSecurityColor()} fontWeight={500}>
                      {getSecurityText()}
                    </Typography>
                    <Box sx={{ flex: 1, ml: 1 }}>
                      <Box
                        sx={{
                          height: 4,
                          borderRadius: 2,
                          background: '#e5e7eb',
                          overflow: 'hidden',
                        }}
                      >
                        <motion.div
                          style={{
                            height: '100%',
                            background: getSecurityColor(),
                            borderRadius: 2,
                          }}
                          initial={{ width: 0 }}
                          animate={{ width: `${(securityLevel === 'high' ? 100 : securityLevel === 'medium' ? 60 : 30)}%` }}
                          transition={{ duration: 0.5 }}
                        />
                      </Box>
                    </Box>
                  </Box>
                </motion.div>
              )}

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 }}
              >
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  disabled={isLoading || isSubmitting || isRateLimited || !isValid}
                  sx={{
                    py: 1.5,
                    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    '&:hover': {
                      background: 'linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%)',
                    },
                    '&:disabled': {
                      background: '#e5e7eb',
                      color: '#9ca3af',
                    },
                  }}
                >
                  {isLoading || isSubmitting ? (
                    <CircularProgress size={24} color="inherit" />
                  ) : (
                    'Sign In'
                  )}
                </Button>
              </motion.div>
            </form>

            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.7 }}
            >
              <Box textAlign="center" mt={3}>
                <Typography variant="body2" color="text.secondary">
                  Don't have an account?{' '}
                  <Link
                    component={RouterLink}
                    to="/register"
                    sx={{
                      color: 'primary.main',
                      textDecoration: 'none',
                      fontWeight: 600,
                      '&:hover': {
                        textDecoration: 'underline',
                      },
                    }}
                  >
                    Sign up
                  </Link>
                </Typography>
              </Box>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.8 }}
            >
              <Box mt={3}>
                <Paper
                  variant="outlined"
                  sx={{
                    p: 2,
                    background: 'rgba(102, 126, 234, 0.05)',
                    borderColor: 'primary.light',
                    borderRadius: 2,
                  }}
                >
                  <Typography variant="body2" color="text.secondary" gutterBottom sx={{ fontWeight: 600 }}>
                    <CheckCircleOutline sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'middle' }} />
                    Demo Account
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Username: <strong>demo_user</strong>
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Password: <strong>DemoPass123!</strong>
                  </Typography>
                  <Button
                    fullWidth
                    variant="outlined"
                    size="small"
                    onClick={handleDemoLogin}
                    disabled={isLoading || isRateLimited}
                    sx={{ mt: 1 }}
                  >
                    Use Demo Account
                  </Button>
                </Paper>
              </Box>
            </motion.div>
          </CardContent>
        </Card>
      </motion.div>
    </Box>
  );
};

export default Login;