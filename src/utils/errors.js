class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource already exists') {
    super(message, 409);
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401);
  }
}

class ForbiddenError extends AppError {
  constructor(message = 'Access forbidden') {
    super(message, 403);
  }
}

class ValidationError extends AppError {
  constructor(message = 'Validation failed', errors = {}) {
    super(message, 400);
    this.errors = errors;
  }
}

export {
  AppError,
  NotFoundError,
  ConflictError,
  AuthenticationError,
  ForbiddenError,
  ValidationError
}; 