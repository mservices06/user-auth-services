import { AppError } from '../utils/errors.js';

/**
 * Custom error handler middleware
 * Processes all errors and sends appropriate HTTP response
 */
export const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  // If it's our custom AppError, use its statusCode
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      ...(err.errors && { errors: err.errors })
    });
  }
  
  // Handle Prisma specific errors
  if (err.name === 'PrismaClientKnownRequestError') {
    // Unique constraint violation
    if (err.code === 'P2002') {
      return res.status(409).json({
        status: 'error',
        message: 'This resource already exists',
        field: err.meta?.target || 'unknown'
      });
    }
    
    // Record not found
    if (err.code === 'P2025') {
      return res.status(404).json({
        status: 'error',
        message: 'Resource not found'
      });
    }
    
    // Invalid data type for field
    if (err.code === 'P2023') {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid input data'
      });
    }
  }
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid authentication token'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication token expired'
    });
  }
  
  // Default to 500 server error
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

export default errorHandler;
