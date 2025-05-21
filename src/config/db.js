// Centralized Prisma Client initialization
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config();

// Create a singleton instance with connection management
class PrismaManager {
  constructor() {
    this.prisma = null;
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxRetries = 5;
    this.retryDelay = 3000; // 3 seconds
  }

  async connect() {
    if (this.isConnected && this.prisma) {
      return this.prisma;
    }

    try {
      if (!this.prisma) {
        this.prisma = new PrismaClient({
          log: ['query', 'warn', 'error'],
          errorFormat: 'pretty',
        });
      }

      // Test the connection
      await this.prisma.$connect();
      this.isConnected = true;
      this.connectionAttempts = 0;
      console.log('Database connection established successfully');
      return this.prisma;
    } catch (error) {
      this.connectionAttempts++;
      console.error(`Database connection failed (attempt ${this.connectionAttempts}):`, error.message);
      
      if (this.connectionAttempts < this.maxRetries) {
        console.log(`Retrying connection in ${this.retryDelay / 1000} seconds...`);
        // Wait and retry
        await new Promise(resolve => setTimeout(resolve, this.retryDelay));
        return this.connect(); // Retry recursively
      } else {
        console.error('Maximum connection retry attempts reached');
        throw new Error(`Failed to connect to database after ${this.maxRetries} attempts: ${error.message}`);
      }
    }
  }

  async disconnect() {
    if (this.prisma && this.isConnected) {
      try {
        await this.prisma.$disconnect();
        this.isConnected = false;
        console.log('Database connection closed successfully');
      } catch (error) {
        console.error('Error while disconnecting from database:', error.message);
      }
    }
  }
}

// Create and export the singleton instance
const prismaManager = new PrismaManager();

// Initialize connection immediately
const prismaClient = await prismaManager.connect().catch(error => {
  console.error('Initial database connection failed:', error.message);
  // Return a PrismaClient instance that will retry on operations
  return prismaManager.prisma || new PrismaClient();
});

// Handle application shutdown
process.on('beforeExit', async () => {
  await prismaManager.disconnect();
});

// Export both as default and named exports
export const prisma = prismaClient;
export { prismaManager };
export default prismaClient; 