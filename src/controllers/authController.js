import { register, login, getProfile } from '../services/authService.js';
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
    
    // Return token and user data
    res.status(201).json({
      token,
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
    
    // Return token and user data
    res.json({
      token,
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

export { registerUser, loginUser, getUserProfile };
