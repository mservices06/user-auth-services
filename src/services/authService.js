// Import the shared Prisma instance
import prisma from '../config/db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Example service methods
const registerUser = async (userData) => {
  const { name, email, password } = userData;
  
  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email }
  });
  
  if (existingUser) {
    throw new Error('Email already in use');
  }
  
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);
  
  // Generate verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  // Create user
  const user = await prisma.user.create({
    data: {
      name,
      email,
      passwordHash,
      verificationToken,
      verificationTokenType: 'VERIFICATION',
      verificationTokenExpires
    }
  });
  
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken
  };
};

const authenticateUser = async (email, password) => {
  // Find user
  const user = await prisma.user.findUnique({
    where: { email }
  });
  
  if (!user) {
    throw new Error('Invalid credentials');
  }
  
  // Check if user is active
  if (!user.isActive) {
    throw new Error('Account is disabled');
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
    
    throw new Error('Invalid credentials');
  }
  
  // Update last login time
  await prisma.user.update({
    where: { id: user.id },
    data: {
      lastLoginAt: new Date(),
      failedLoginAttempts: 0
    }
  });
  
  return user;
};

export { registerUser, authenticateUser };
