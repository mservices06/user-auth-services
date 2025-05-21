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

export { register, login, getProfile };
