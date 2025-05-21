// Import the shared Prisma instance
import prisma from '../config/db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { ConflictError, NotFoundError, AuthenticationError, ForbiddenError } from '../utils/errors.js';

/**
 * Register a new user
 * @param {Object} userData - User registration data
 * @param {string} userData.name - User's name
 * @param {string} userData.email - User's email
 * @param {string} userData.password - User's password
 * @returns {Object} Created user object (excluding sensitive fields)
 * @throws {ConflictError} If email already exists
 */
const register = async ({ name, email, password }) => {
  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email }
  });
  
  if (existingUser) {
    throw new ConflictError('Email already in use');
  }
  
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);
  
  // Create user in a transaction
  const user = await prisma.$transaction(async (tx) => {
    // Create the user record
    const newUser = await tx.user.create({
      data: {
        name,
        email,
        passwordHash
      },
      select: {
        id: true,
        name: true,
        email: true,
        roles: true,
        isActive: true,
        createdAt: true
      }
    });
    
    return newUser;
  });
  
  return user;
};

/**
 * Login a user
 * @param {Object} credentials - User login credentials
 * @param {string} credentials.email - User's email
 * @param {string} credentials.password - User's password
 * @returns {Object} User object for token generation
 * @throws {NotFoundError} If user not found
 * @throws {AuthenticationError} If password is invalid
 * @throws {ForbiddenError} If account is locked or disabled
 */
const login = async ({ email, password }) => {
  // Find user
  const user = await prisma.user.findUnique({
    where: { email }
  });
  
  if (!user) {
    throw new NotFoundError('User not found');
  }
  
  // Check if user is active
  if (!user.isActive) {
    throw new ForbiddenError('Account is disabled');
  }
  
  // Check if account is locked
  if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
    throw new ForbiddenError('Account is temporarily locked');
  }
  
  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    // Update failed login attempts
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: {
          increment: 1
        }
      }
    });
    
    throw new AuthenticationError('Invalid credentials');
  }
  
  // Update last login time and reset failed attempts
  await prisma.user.update({
    where: { id: user.id },
    data: {
      lastLoginAt: new Date(),
      failedLoginAttempts: 0
    }
  });
  
  // Return user data (excluding sensitive fields)
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    roles: user.roles
  };
};

/**
 * Get user profile
 * @param {string} userId - User ID
 * @returns {Object} User profile (excluding sensitive fields)
 * @throws {NotFoundError} If user not found
 */
const getProfile = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      roles: true,
      isActive: true,
      emailVerified: true,
      twoFactorEnabled: true,
      lastLoginAt: true,
      createdAt: true,
      updatedAt: true
    }
  });
  
  if (!user) {
    throw new NotFoundError('User not found');
  }
  
  return user;
};

/**
 * Issue a new refresh token for a user
 * @param {string} userId - User ID
 * @param {string} userAgent - Client user agent
 * @param {string} ipAddress - Client IP address
 * @returns {Object} Refresh token data with token value and expiry
 */
const issueRefreshToken = async (userId, userAgent, ipAddress) => {
  // Generate a secure random token
  const tokenBytes = crypto.randomBytes(40);
  const token = tokenBytes.toString('hex');
  
  // Calculate expiration date (30 days)
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);
  
  // Store token in database
  const refreshToken = await prisma.refreshToken.create({
    data: {
      token,
      userId,
      userAgent,
      ipAddress,
      expiresAt
    }
  });
  
  return {
    token: refreshToken.token,
    expiresAt: refreshToken.expiresAt
  };
};

/**
 * Refresh an access token using a refresh token
 * @param {string} refreshToken - Refresh token string
 * @param {string} userAgent - Client user agent
 * @param {string} ipAddress - Client IP address
 * @returns {Object} New access token and optionally a new refresh token
 * @throws {NotFoundError} If token not found
 * @throws {AuthenticationError} If token is revoked or expired
 */
const refreshAccessToken = async (refreshToken, userAgent, ipAddress) => {
  // Find the refresh token
  const tokenRecord = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
    include: { user: true }
  });
  
  // Validate token existence and status
  if (!tokenRecord) {
    throw new NotFoundError('Invalid refresh token');
  }
  
  if (tokenRecord.revokedAt) {
    throw new AuthenticationError('Token has been revoked');
  }
  
  if (new Date(tokenRecord.expiresAt) < new Date()) {
    throw new AuthenticationError('Token has expired');
  }
  
  // Verify user is still active
  if (!tokenRecord.user.isActive) {
    throw new ForbiddenError('User account is disabled');
  }
  
  // Create a new access token
  const accessToken = jwt.sign(
    { userId: tokenRecord.userId },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
  
  // Determine if we should rotate the refresh token
  // Rotation can be triggered by proximity to expiration or security policy
  const shouldRotateToken = new Date(tokenRecord.expiresAt).getTime() - new Date().getTime() < 7 * 24 * 60 * 60 * 1000; // 7 days
  
  let newRefreshToken = null;
  
  if (shouldRotateToken) {
    // Issue a new refresh token and revoke the old one in a transaction
    await prisma.$transaction(async (tx) => {
      // Revoke the old token
      await tx.refreshToken.update({
        where: { id: tokenRecord.id },
        data: { revokedAt: new Date() }
      });
      
      // Create a new token
      const tokenBytes = crypto.randomBytes(40);
      const token = tokenBytes.toString('hex');
      
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 30);
      
      const newToken = await tx.refreshToken.create({
        data: {
          token,
          userId: tokenRecord.userId,
          userAgent,
          ipAddress,
          expiresAt
        }
      });
      
      newRefreshToken = {
        token: newToken.token,
        expiresAt: newToken.expiresAt
      };
    });
  }
  
  return {
    accessToken,
    refreshToken: newRefreshToken || { token: tokenRecord.token, expiresAt: tokenRecord.expiresAt }
  };
};

/**
 * Revoke a refresh token
 * @param {string} token - Refresh token to revoke
 * @returns {Object} Confirmation of revocation
 * @throws {NotFoundError} If token not found
 */
const revokeRefreshToken = async (token) => {
  // Find the token
  const tokenRecord = await prisma.refreshToken.findUnique({
    where: { token }
  });
  
  if (!tokenRecord) {
    throw new NotFoundError('Invalid refresh token');
  }
  
  // If already revoked, nothing to do
  if (tokenRecord.revokedAt) {
    return { revoked: true, alreadyRevoked: true };
  }
  
  // Mark as revoked
  await prisma.refreshToken.update({
    where: { id: tokenRecord.id },
    data: { revokedAt: new Date() }
  });
  
  return { revoked: true, alreadyRevoked: false };
};

export { register, login, getProfile, issueRefreshToken, refreshAccessToken, revokeRefreshToken };
