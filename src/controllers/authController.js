import { register, login, getProfile, refreshAccessToken, revokeRefreshToken, issueRefreshToken } from '../services/authService.js';
import { signToken } from '../utils/jwtHelper.js';
import { 
  ConflictError, 
  NotFoundError, 
  AuthenticationError, 
  ForbiddenError,
  ValidationError 
} from '../utils/errors.js';

/**
 * Register a new user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const registerUser = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    
    // Register the user
    const user = await register({ name, email, password });
    
    // Generate JWT token
    const token = signToken({ userId: user.id });
    
    // Issue a refresh token
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress = req.ip || req.connection.remoteAddress;
    const refreshToken = await issueRefreshToken(user.id, userAgent, ipAddress);
    
    // Return token and user data
    res.status(201).json({
      accessToken: token,
      refreshToken: refreshToken.token,
      expiresAt: refreshToken.expiresAt,
      user
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Login user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Authenticate the user
    const user = await login({ email, password });
    
    // Generate JWT token
    const token = signToken({ userId: user.id });
    
    // Issue a refresh token
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress = req.ip || req.connection.remoteAddress;
    const refreshToken = await issueRefreshToken(user.id, userAgent, ipAddress);
    
    // Return token and user data
    res.json({
      accessToken: token,
      refreshToken: refreshToken.token,
      expiresAt: refreshToken.expiresAt,
      user
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get authenticated user's profile
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const getUserProfile = async (req, res, next) => {
  try {
    const userId = req.userId;
    
    // Get user profile
    const user = await getProfile(userId);
    
    // Return user profile
    res.json({
      user
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Refresh access token using a refresh token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;
    
    if (!token) {
      throw new ValidationError('Refresh token is required');
    }
    
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress = req.ip || req.connection.remoteAddress;
    
    // Refresh the access token
    const tokens = await refreshAccessToken(token, userAgent, ipAddress);
    
    // Return the new tokens
    res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken.token,
      expiresAt: tokens.refreshToken.expiresAt
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Logout user and revoke refresh token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      throw new ValidationError('Refresh token is required');
    }
    
    // Revoke the refresh token
    await revokeRefreshToken(refreshToken);
    
    // Return success with no content
    res.status(204).end();
  } catch (error) {
    next(error);
  }
};

export { registerUser, loginUser, getUserProfile, refreshToken, logout };
