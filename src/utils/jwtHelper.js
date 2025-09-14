// JWT Helper functions for token generation and verification

import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * Sign a JWT token for a user
 * @param {Object} payload - Data to include in the token
 * @param {string} expiresIn - Token expiration time (default from env or 24h)
 * @returns {string} Signed JWT token
 */
const signToken = (payload, expiresIn = JWT_EXPIRES_IN) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
};

/**
 * Verify a JWT token
 * @param {string} token - JWT token to verify
 * @returns {Object} Decoded token payload
 * @throws {Error} If token is invalid
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    throw new Error('Invalid token: ' + error.message);
  }
};

export { signToken, verifyToken };
