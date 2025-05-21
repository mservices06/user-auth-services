import { z } from 'zod';
import { ValidationError } from '../utils/errors.js';

/**
 * Validate request against a Zod schema
 * @param {Object} schema - Zod schema for validation
 * @returns {Function} Express middleware function
 */
export const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = {};
      error.errors.forEach((err) => {
        errorMessages[err.path.join('.')] = err.message;
      });
      next(new ValidationError('Validation failed', errorMessages));
    } else {
      next(error);
    }
  }
};

/**
 * Registration validation schema
 */
export const registerSchema = z.object({
  name: z.string()
    .min(2, 'Name must be at least 2 characters long')
    .max(50, 'Name must be less than 50 characters')
    .trim(),
  
  email: z.string()
    .email('Please provide a valid email address')
    .trim()
    .toLowerCase(),
  
  password: z.string()
    .min(6, 'Password must be at least 6 characters long')
    .regex(/\d/, 'Password must contain at least one number')
    .regex(/[a-zA-Z]/, 'Password must contain at least one letter')
});

/**
 * Login validation schema
 */
export const loginSchema = z.object({
  email: z.string()
    .email('Please provide a valid email address')
    .trim()
    .toLowerCase(),
  
  password: z.string()
    .min(1, 'Password is required')
});

/**
 * Middleware for validating registration request
 */
export const registerValidation = validate(registerSchema);

/**
 * Middleware for validating login request
 */
export const loginValidation = validate(loginSchema);

export default {
  registerValidation,
  loginValidation
};