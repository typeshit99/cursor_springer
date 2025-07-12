import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Avatar,
  Chip,
  Divider,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  LinearProgress,
  Tooltip,
  Badge,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import { motion, AnimatePresence } from 'framer-motion';
import {
  SecurityOutlined,
  PersonOutlined,
  EmailOutlined,
  LockOutlined,
  LogoutOutlined,
  RefreshOutlined,
  CheckCircleOutline,
  WarningAmber,
  InfoOutlined,
  ShieldOutlined,
  VerifiedUserOutlined,
  TimerOutlined,
  KeyOutlined,
  HistoryOutlined,
  SettingsOutlined,
  VisibilityOutlined,
  VisibilityOffOutlined,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface SecurityInfo {
  lastLogin: string;
  loginCount: number;
  securityScore: number;
  threatsBlocked: number;
  sessionDuration: string;
}

const Dashboard: React.FC = () => {
  const { user, logout, refreshAccessToken } = useAuth();
  const navigate = useNavigate();
  const [securityInfo, setSecurityInfo] = useState<SecurityInfo>({
    lastLogin: new Date().toLocaleString(),
    loginCount: 1,
    securityScore: 95,
    threatsBlocked: 0,
    sessionDuration: '0:00',
  });
  const [showToken, setShowToken] = useState(false);
  const [sessionStart] = useState(Date.now());
  const [sessionTime, setSessionTime] = useState('0:00');
  const [securityDialogOpen, setSecurityDialogOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Session timer
  useEffect(() => {
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - sessionStart) / 1000);
      const minutes = Math.floor(elapsed / 60);
      const seconds = elapsed % 60;
      setSessionTime(`${minutes}:${seconds.toString().padStart(2, '0')}`);
    }, 1000);

    return () => clearInterval(interval);
  }, [sessionStart]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleRefreshToken = async () => {
    setIsRefreshing(true);
    try {
      const success = await refreshAccessToken();
      if (success) {
        // Show success message
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    } finally {
      setIsRefreshing(false);
    }
  };

  const getSecurityColor = (score: number) => {
    if (score >= 90) return '#10b981';
    if (score >= 70) return '#f59e0b';
    return '#ef4444';
  };

  const getSecurityStatus = (score: number) => {
    if (score >= 90) return 'Excellent';
    if (score >= 70) return 'Good';
    return 'Needs Attention';
  };

  const securityFeatures = [
    { name: 'JWT Authentication', status: 'Active', icon: <KeyOutlined /> },
    { name: 'Rate Limiting', status: 'Active', icon: <TimerOutlined /> },
    { name: 'Input Validation', status: 'Active', icon: <ShieldOutlined /> },
    { name: 'XSS Protection', status: 'Active', icon: <SecurityOutlined /> },
    { name: 'CSRF Protection', status: 'Active', icon: <VerifiedUserOutlined /> },
    { name: 'SQL Injection Protection', status: 'Active', icon: <CheckCircleOutline /> },
  ];

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: 'background.default', p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Grid container alignItems="center" justifyContent="space-between">
            <Grid item>
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 }}
              >
                <Typography variant="h3" component="h1" sx={{ fontWeight: 700, color: '#1e293b' }}>
                  Secure Dashboard
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Welcome to your protected workspace
                </Typography>
              </motion.div>
            </Grid>
            <Grid item>
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 }}
              >
                <Button
                  variant="outlined"
                  startIcon={<LogoutOutlined />}
                  onClick={handleLogout}
                  sx={{ mr: 2 }}
                >
                  Logout
                </Button>
                <Button
                  variant="contained"
                  startIcon={<RefreshOutlined />}
                  onClick={handleRefreshToken}
                  disabled={isRefreshing}
                >
                  {isRefreshing ? 'Refreshing...' : 'Refresh Token'}
                </Button>
              </motion.div>
            </Grid>
          </Grid>
        </Box>

        <Grid container spacing={3}>
          {/* User Profile Card */}
          <Grid item xs={12} md={4}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <Card sx={{ height: '100%', borderRadius: 3 }}>
                <CardContent sx={{ p: 3 }}>
                  <Box textAlign="center" mb={3}>
                    <Avatar
                      sx={{
                        width: 80,
                        height: 80,
                        mx: 'auto',
                        mb: 2,
                        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                      }}
                    >
                      <PersonOutlined sx={{ fontSize: 40 }} />
                    </Avatar>
                    <Typography variant="h5" component="h2" gutterBottom sx={{ fontWeight: 600 }}>
                      {user?.username}
                    </Typography>
                    <Chip
                      label="Verified User"
                      color="success"
                      size="small"
                      icon={<VerifiedUserOutlined />}
                    />
                  </Box>

                  <Divider sx={{ my: 2 }} />

                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <PersonOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Username"
                        secondary={user?.username}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <EmailOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Email"
                        secondary="user@example.com"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <TimerOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Session Duration"
                        secondary={sessionTime}
                      />
                    </ListItem>
                  </List>

                  <Box mt={2}>
                    <Button
                      fullWidth
                      variant="outlined"
                      startIcon={showToken ? <VisibilityOffOutlined /> : <VisibilityOutlined />}
                      onClick={() => setShowToken(!showToken)}
                    >
                      {showToken ? 'Hide Token' : 'Show Token'}
                    </Button>
                  </Box>

                  {showToken && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                    >
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 2,
                          mt: 2,
                          background: '#f8fafc',
                          wordBreak: 'break-all',
                          fontSize: '0.75rem',
                        }}
                      >
                        <Typography variant="caption" color="text.secondary">
                          Access Token (JWT)
                        </Typography>
                        <Typography variant="body2" fontFamily="monospace">
                          {user?.token?.substring(0, 50)}...
                        </Typography>
                      </Paper>
                    </motion.div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          {/* Security Overview */}
          <Grid item xs={12} md={8}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <Card sx={{ height: '100%', borderRadius: 3 }}>
                <CardContent sx={{ p: 3 }}>
                  <Box display="flex" alignItems="center" mb={3}>
                    <SecurityOutlined sx={{ fontSize: 32, color: 'primary.main', mr: 2 }} />
                    <Typography variant="h5" component="h2" sx={{ fontWeight: 600 }}>
                      Security Overview
                    </Typography>
                  </Box>

                  <Grid container spacing={3}>
                    {/* Security Score */}
                    <Grid item xs={12} sm={6}>
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 2,
                          textAlign: 'center',
                          borderColor: getSecurityColor(securityInfo.securityScore),
                        }}
                      >
                        <Typography variant="h4" sx={{ color: getSecurityColor(securityInfo.securityScore), fontWeight: 700 }}>
                          {securityInfo.securityScore}%
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Security Score
                        </Typography>
                        <Chip
                          label={getSecurityStatus(securityInfo.securityScore)}
                          color={securityInfo.securityScore >= 90 ? 'success' : securityInfo.securityScore >= 70 ? 'warning' : 'error'}
                          size="small"
                          sx={{ mt: 1 }}
                        />
                      </Paper>
                    </Grid>

                    {/* Threats Blocked */}
                    <Grid item xs={12} sm={6}>
                      <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="h4" color="success.main" sx={{ fontWeight: 700 }}>
                          {securityInfo.threatsBlocked}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Threats Blocked
                        </Typography>
                        <Chip
                          label="Protected"
                          color="success"
                          size="small"
                          icon={<ShieldOutlined />}
                          sx={{ mt: 1 }}
                        />
                      </Paper>
                    </Grid>
                  </Grid>

                  <Box mt={3}>
                    <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                      Security Features Status
                    </Typography>
                    <Grid container spacing={2}>
                      {securityFeatures.map((feature, index) => (
                        <Grid item xs={12} sm={6} key={feature.name}>
                          <motion.div
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: 0.6 + index * 0.1 }}
                          >
                            <Paper
                              variant="outlined"
                              sx={{
                                p: 2,
                                display: 'flex',
                                alignItems: 'center',
                                borderColor: 'success.main',
                              }}
                            >
                              <Box sx={{ color: 'success.main', mr: 2 }}>
                                {feature.icon}
                              </Box>
                              <Box>
                                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                  {feature.name}
                                </Typography>
                                <Chip
                                  label={feature.status}
                                  color="success"
                                  size="small"
                                  sx={{ mt: 0.5 }}
                                />
                              </Box>
                            </Paper>
                          </motion.div>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          {/* Security Alerts */}
          <Grid item xs={12}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7 }}
            >
              <Card sx={{ borderRadius: 3 }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                    Security Alerts & Recommendations
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Alert
                        severity="success"
                        icon={<CheckCircleOutline />}
                        sx={{ mb: 2 }}
                      >
                        <Typography variant="body2" fontWeight={600}>
                          Strong Password Detected
                        </Typography>
                        <Typography variant="body2">
                          Your password meets all security requirements.
                        </Typography>
                      </Alert>
                    </Grid>
                    
                    <Grid item xs={12} md={6}>
                      <Alert
                        severity="info"
                        icon={<InfoOutlined />}
                        sx={{ mb: 2 }}
                      >
                        <Typography variant="body2" fontWeight={600}>
                          Session Active
                        </Typography>
                        <Typography variant="body2">
                          Your session is secure and active. Token will auto-refresh.
                        </Typography>
                      </Alert>
                    </Grid>
                  </Grid>

                  <Box mt={2}>
                    <Button
                      variant="outlined"
                      startIcon={<SettingsOutlined />}
                      onClick={() => setSecurityDialogOpen(true)}
                    >
                      Security Settings
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          {/* Activity Log */}
          <Grid item xs={12}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.8 }}
            >
              <Card sx={{ borderRadius: 3 }}>
                <CardContent sx={{ p: 3 }}>
                  <Box display="flex" alignItems="center" mb={2}>
                    <HistoryOutlined sx={{ fontSize: 24, color: 'primary.main', mr: 2 }} />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Recent Activity
                    </Typography>
                  </Box>
                  
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircleOutline color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Login successful"
                        secondary={securityInfo.lastLogin}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <ShieldOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Security scan completed"
                        secondary="All systems secure"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <KeyOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary="JWT token validated"
                        secondary="Token is valid and secure"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>
        </Grid>
      </motion.div>

      {/* Security Settings Dialog */}
      <Dialog
        open={securityDialogOpen}
        onClose={() => setSecurityDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box display="flex" alignItems="center">
            <SecurityOutlined sx={{ mr: 1 }} />
            Security Settings
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            Your account is protected with enterprise-grade security measures:
          </Typography>
          
          <List>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutline color="success" />
              </ListItemIcon>
              <ListItemText
                primary="JWT Authentication"
                secondary="Secure token-based authentication with automatic refresh"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutline color="success" />
              </ListItemIcon>
              <ListItemText
                primary="Rate Limiting"
                secondary="Protection against brute force attacks"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutline color="success" />
              </ListItemIcon>
              <ListItemText
                primary="Input Validation"
                secondary="Comprehensive validation and sanitization"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutline color="success" />
              </ListItemIcon>
              <ListItemText
                primary="XSS Protection"
                secondary="Cross-site scripting attack prevention"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutline color="success" />
              </ListItemIcon>
              <ListItemText
                primary="CSRF Protection"
                secondary="Cross-site request forgery protection"
              />
            </ListItem>
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSecurityDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard;