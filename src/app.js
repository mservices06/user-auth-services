// Import dependencies
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import { prisma, prismaManager } from './config/db.js';

// Import routes
import userRoutes from './routes/userRoutes.js';
import authRoutes from './routes/authRoutes.js';

// Create Express app
const app = express();

// Apply middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Database connection middleware
app.use(async (req, res, next) => {
  // Check database connection on each request
  if (!prismaManager.isConnected) {
    try {
      await prismaManager.connect();
    } catch (error) {
      console.error('Database connection error in middleware:', error.message);
      // Allow the request to continue, but it may fail if DB access is needed
    }
  }
  next();
});

// Apply routes
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);

// Database error handler middleware
app.use(async (err, req, res, next) => {
  // Check if error is a Prisma error
  if (err.name === 'PrismaClientInitializationError' || 
      err.name === 'PrismaClientKnownRequestError' || 
      err.name === 'PrismaClientRustPanicError' || 
      err.name === 'PrismaClientUnknownRequestError') {
    
    console.error('Prisma error detected:', err.message);
    
    // Try to reconnect to the database
    try {
      await prismaManager.connect();
      // If reconnection successful, you could retry the operation
      // For now, just return a database error
      return res.status(503).json({
        status: 'error',
        message: 'Database error occurred, please try again',
        retryable: true
      });
    } catch (reconnectError) {
      // Cannot reconnect to database
      return res.status(503).json({
        status: 'error',
        message: 'Database service unavailable',
        retryable: false
      });
    }
  }
  
  // Pass to general error handler if not a Prisma error
  next(err);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Export app for server.js to use
export default app;
