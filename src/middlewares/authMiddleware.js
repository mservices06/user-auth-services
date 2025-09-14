import { verifyToken } from '../utils/jwtHelper.js';
import { AuthenticationError, ForbiddenError } from '../utils/errors.js';
import prisma from '../config/db.js';

/**
 * Middleware to verify authentication token and attach user to request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
export const authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Authorization token required');
    }
    
    const token = authHeader.split(' ')[1];
    
    // Verify token
    const decoded = verifyToken(token);
    
    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { 
        id: true,
        isActive: true,
        lockUntil: true,
        roles: true
      }
    });
    
    // Check if user exists
    if (!user) {
      throw new AuthenticationError('User no longer exists');
    }
    
    // Check if user is active
    if (!user.isActive) {
      throw new ForbiddenError('Account has been deactivated');
    }
    
    // Check if account is locked
    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      throw new ForbiddenError('Account is temporarily locked');
    }
    
    // Attach user to request object
    req.userId = user.id;
    req.userRoles = user.roles;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return next(new AuthenticationError('Invalid or expired token'));
    }
    next(error);
  }
};

/**
 * Middleware to check if user has required roles
 * @param {string[]} roles - Array of required roles
 * @returns {Function} Express middleware
 */
export const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.userId || !req.userRoles) {
      return next(new AuthenticationError('Authentication required'));
    }
    
    // Check if user has required roles
    const hasRole = req.userRoles.some(role => roles.includes(role));
    if (!hasRole) {
      return next(new ForbiddenError('Insufficient permissions'));
    }
    
    next();
  };
};

export default { authenticate, authorize };
