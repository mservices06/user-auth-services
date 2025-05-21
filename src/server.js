// Import dependencies
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { prisma, prismaManager } from './config/db.js';

// Import routes
import userRoutes from './routes/userRoutes.js';
import authRoutes from './routes/authRoutes.js';

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Database health check middleware
app.use(async (req, res, next) => {
  if (!prismaManager.isConnected) {
    try {
      // Try to reconnect if connection was lost
      await prismaManager.connect();
    } catch (error) {
      console.error('Database reconnection failed in middleware:', error.message);
      // Continue anyway to allow non-DB routes to work
    }
  }
  next();
});

// Routes
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  
  // First close the server to stop accepting new connections
  server.close(() => {
    console.log('HTTP server closed');
  });
  
  try {
    // Disconnect from database
    await prismaManager.disconnect();
    console.log('All connections closed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
};

// Listen for termination signals
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  gracefulShutdown('uncaughtException');
});
