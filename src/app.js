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

// Database health check middleware
app.use(async (req, res, next) => {
  if (!prismaManager.isConnected) {
    try {
      // Try to reconnect if connection was lost
      await prismaManager.connect();
    } catch (error) {
      console.error('☠️ Database reconnection failed in middleware:', error.message);
      // Continue anyway to allow non-DB routes to work
    }
  }
  next();
});

// Apply routes
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).json({ 
      status: 'ok', 
      database: 'connected',
      connectionAttempts: prismaManager.connectionAttempts
    });
  } catch (error) {
    console.error('Health check failed:', error);
    
    // Try to reconnect
    try {
      await prismaManager.connect();
      res.status(200).json({ 
        status: 'recovered', 
        database: 'reconnected',
        connectionAttempts: prismaManager.connectionAttempts
      });
    } catch (reconnectError) {
      res.status(500).json({ 
        status: 'error', 
        database: 'disconnected',
        error: error.message,
        connectionAttempts: prismaManager.connectionAttempts
      });
    }
  }
});

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
      return next(err);
    } catch (reconnectError) {
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

// General error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Export app for server.js to use
export default app;
