import express from 'express';
import { registerUser, loginUser, getUserProfile, refreshToken, logout } from '../controllers/authController.js';
import { authenticate } from '../middlewares/authMiddleware.js';
import { 
  registerValidation, 
  loginValidation, 
  refreshTokenValidation, 
  logoutValidation 
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

export default router;
