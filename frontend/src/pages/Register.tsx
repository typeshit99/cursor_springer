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
  Stepper,
  Step,
  StepLabel,
  Chip,
  Divider,
  LinearProgress,
} from '@mui/material';
import { useNavigate, Link as RouterLink } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Visibility, 
  VisibilityOff, 
  PersonAddOutlined, 
  EmailOutlined,
  PersonOutlined,
  LockOutlined,
  SecurityOutlined,
  ShieldOutlined,
  CheckCircleOutline,
  ErrorOutline,
  WarningAmber,
  TimerOutlined,
  VerifiedUserOutlined,
  PasswordOutlined
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
  email: yup
    .string()
    .required('Email is required')
    .email('Please enter a valid email address')
    .test('no-suspicious-patterns', 'Email contains restricted patterns', (value) => {
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
  confirmPassword: yup
    .string()
    .required('Please confirm your password')
    .oneOf([yup.ref('password')], 'Passwords must match'),
}).required();

type FormData = yup.InferType<typeof schema>;

const Register: React.FC = () => {
  const { register: registerUser, isLoading, isRateLimited, rateLimitReset } = useAuth();
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [securityLevel, setSecurityLevel] = useState<'low' | 'medium' | 'high'>('low');
  const [timeRemaining, setTimeRemaining] = useState<number>(0);
  const [activeStep, setActiveStep] = useState(0);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    setValue,
    watch,
    trigger,
  } = useForm<FormData>({
    resolver: yupResolver(schema),
    mode: 'onChange',
  });

  const watchedPassword = watch('password', '');
  const watchedUsername = watch('username', '');
  const watchedEmail = watch('email', '');

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

  // Auto-advance steps based on field completion
  useEffect(() => {
    if (watchedUsername && !errors.username) {
      setActiveStep(1);
    } else if (watchedEmail && !errors.email) {
      setActiveStep(2);
    } else if (watchedPassword && !errors.password && securityLevel === 'high') {
      setActiveStep(3);
    }
  }, [watchedUsername, watchedEmail, watchedPassword, errors, securityLevel]);

  const onSubmit = async (data: FormData) => {
    setError(null);
    const success = await registerUser(data.username, data.email, data.password);
    if (success) {
      navigate('/login');
    }
  };

  const handleShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const handleShowConfirmPassword = () => {
    setShowConfirmPassword(!showConfirmPassword);
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

  const steps = ['Username', 'Email', 'Password', 'Confirm'];

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
          top: '15%',
          right: '10%',
          width: 120,
          height: 120,
          borderRadius: '50%',
          background: 'rgba(255, 255, 255, 0.1)',
        }}
        animate={{
          y: [0, -30, 0],
          scale: [1, 1.2, 1],
        }}
        transition={{
          duration: 5,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      <motion.div
        style={{
          position: 'absolute',
          bottom: '15%',
          left: '10%',
          width: 80,
          height: 80,
          borderRadius: '50%',
          background: 'rgba(255, 255, 255, 0.08)',
        }}
        animate={{
          y: [0, 20, 0],
          scale: [1, 0.8, 1],
        }}
        transition={{
          duration: 4,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        style={{ width: '100%', maxWidth: 500 }}
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
                  <PersonAddOutlined sx={{ color: 'white', fontSize: 32 }} />
                </Box>
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700, color: '#1e293b' }}>
                  Create Account
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Join our secure platform today
                </Typography>
              </motion.div>
            </Box>

            {/* Progress Stepper */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <Stepper activeStep={activeStep} sx={{ mb: 3 }}>
                {steps.map((label, index) => (
                  <Step key={label}>
                    <StepLabel>{label}</StepLabel>
                  </Step>
                ))}
              </Stepper>
            </motion.div>

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
                transition={{ delay: 0.5 }}
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
                transition={{ delay: 0.6 }}
              >
                <TextField
                  {...register('email')}
                  fullWidth
                  label="Email"
                  type="email"
                  variant="outlined"
                  margin="normal"
                  error={!!errors.email}
                  helperText={errors.email?.message}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <EmailOutlined color="action" />
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
                transition={{ delay: 0.7 }}
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
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.8 }}
              >
                <TextField
                  {...register('confirmPassword')}
                  fullWidth
                  label="Confirm Password"
                  type={showConfirmPassword ? 'text' : 'password'}
                  variant="outlined"
                  margin="normal"
                  error={!!errors.confirmPassword}
                  helperText={errors.confirmPassword?.message}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <PasswordOutlined color="action" />
                      </InputAdornment>
                    ),
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          aria-label="toggle confirm password visibility"
                          onClick={handleShowConfirmPassword}
                          edge="end"
                        >
                          {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                  sx={{ mb: 2 }}
                  disabled={isRateLimited}
                />
              </motion.div>

              {/* Security requirements */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.9 }}
              >
                <Paper
                  variant="outlined"
                  sx={{
                    p: 2,
                    mb: 3,
                    background: 'rgba(102, 126, 234, 0.05)',
                    borderColor: 'primary.light',
                    borderRadius: 2,
                  }}
                >
                  <Typography variant="body2" color="text.secondary" gutterBottom sx={{ fontWeight: 600 }}>
                    <SecurityOutlined sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'middle' }} />
                    Security Requirements
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                      • Username: 3-20 characters, letters, numbers, underscores only
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                      • Password: Minimum 8 characters with uppercase, lowercase, number, and special character
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                      • No restricted patterns (admin, root, system, etc.)
                    </Typography>
                  </Box>
                </Paper>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1.0 }}
              >
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  disabled={isLoading || isSubmitting || isRateLimited || !isValid || securityLevel !== 'high'}
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
                    'Create Account'
                  )}
                </Button>
              </motion.div>
            </form>

            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1.1 }}
            >
              <Box textAlign="center" mt={3}>
                <Typography variant="body2" color="text.secondary">
                  Already have an account?{' '}
                  <Link
                    component={RouterLink}
                    to="/login"
                    sx={{
                      color: 'primary.main',
                      textDecoration: 'none',
                      fontWeight: 600,
                      '&:hover': {
                        textDecoration: 'underline',
                      },
                    }}
                  >
                    Sign in
                  </Link>
                </Typography>
              </Box>
            </motion.div>
          </CardContent>
        </Card>
      </motion.div>
    </Box>
  );
};

export default Register;