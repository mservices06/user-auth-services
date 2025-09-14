import express from 'express';
import { 
  registerUser, 
  loginUser, 
  getUserProfile, 
  refreshToken, 
  logout,
  resendVerificationEmail,
  verifyUserEmail,
  forgotUserPassword,
  resetUserPassword
} from '../controllers/authController.js';
import { authenticate } from '../middlewares/authMiddleware.js';
import { 
  registerValidation, 
  loginValidation, 
  refreshTokenValidation, 
  logoutValidation,
  resendVerificationValidation,
  forgotPasswordValidation,
  resetPasswordValidation
} from '../middlewares/validationMiddleware.js';

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', registerValidation, registerUser);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user & get token
 * @access  Public
 */
router.post('/login', loginValidation, loginUser);

/**
 * @route   GET /api/auth/me
 * @desc    Get authenticated user profile
 * @access  Private
 */
router.get('/me', authenticate, getUserProfile);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post('/refresh-token', refreshTokenValidation, refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and revoke refresh token
 * @access  Private
 */
router.post('/logout', authenticate, logoutValidation, logout);

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend verification email
 * @access  Public
 */
router.post('/resend-verification', resendVerificationValidation, resendVerificationEmail);

/**
 * @route   GET /api/auth/verify-email
 * @desc    Verify user email with token
 * @access  Public
 */
router.get('/verify-email', verifyUserEmail);

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Initiate password reset process
 * @access  Public
 */
router.post('/forgot-password', forgotPasswordValidation, forgotUserPassword);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', resetPasswordValidation, resetUserPassword);

export default router;
