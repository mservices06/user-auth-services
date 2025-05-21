// Import the shared Prisma instance
import prisma from '../config/db.js';

// Example controller methods
const getAllUsers = async (req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        roles: true,
        isActive: true,
        createdAt: true
      }
    });
    
    res.json({ users });
  } catch (error) {
    console.error('Error fetching users:', error);
    
    // Handle specific Prisma errors
    if (error.code === 'P2002') {
      // Unique constraint violation
      return res.status(409).json({ error: 'Conflict in database operation' });
    } else if (error.code === 'P2025') {
      // Record not found
      return res.status(404).json({ error: 'Not found' });
    }
    
    // Pass error to the global error handler
    next(error);
  }
};

const getUserById = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    if (!id) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        roles: true,
        isActive: true,
        createdAt: true
      }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
  } catch (error) {
    console.error('Error fetching user:', error);
    
    // Handle specific database errors
    if (error.name === 'PrismaClientKnownRequestError') {
      // Handle specific error codes
      if (error.code === 'P2023') {
        return res.status(400).json({ error: 'Invalid ID format' });
      }
    }
    
    // Pass other errors to the error handling middleware
    next(error);
  }
};

// Create a new user with transaction support
const createUser = async (req, res, next) => {
  const { name, email, password, roles } = req.body;
  
  // Input validation
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  
  try {
    // Use a transaction to ensure data consistency
    const result = await prisma.$transaction(async (tx) => {
      // Check if user already exists
      const existingUser = await tx.user.findUnique({
        where: { email }
      });
      
      if (existingUser) {
        throw new Error('Email already in use');
      }
      
      // Create the user
      const user = await tx.user.create({
        data: {
          name,
          email,
          passwordHash: password, // In a real app, hash the password
          roles: roles || undefined
        },
        select: {
          id: true,
          name: true,
          email: true,
          roles: true,
          createdAt: true
        }
      });
      
      return user;
    }, {
      // Transaction options
      maxWait: 5000, // max 5s to acquire connection
      timeout: 10000, // max 10s to process transaction
      isolationLevel: 'Serializable' // highest isolation level
    });
    
    res.status(201).json({ user: result });
  } catch (error) {
    console.error('Error creating user:', error);
    
    if (error.message === 'Email already in use') {
      return res.status(409).json({ error: error.message });
    }
    
    // Database-specific error handling
    if (error.code === 'P2002') {
      return res.status(409).json({ 
        error: 'A user with this email already exists' 
      });
    }
    
    next(error);
  }
};

export { getAllUsers, getUserById, createUser };
