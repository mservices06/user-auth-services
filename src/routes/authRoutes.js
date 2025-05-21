import express from 'express';
import { registerUser, authenticateUser } from '../services/authService.js';

const router = express.Router();

// Registration route
router.post('/register', async (req, res, next) => {
  try {
    const userData = req.body;
    const result = await registerUser(userData);
    res.status(201).json({ 
      message: 'User registered successfully',
      user: result
    });
  } catch (error) {
    if (error.message === 'Email already in use') {
      return res.status(409).json({ error: error.message });
    }
    next(error);
  }
});

// Login route
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await authenticateUser(email, password);
    
    // Here you would generate tokens, but we'll just return user info for now
    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        roles: user.roles
      }
    });
  } catch (error) {
    if (error.message === 'Invalid credentials' || error.message === 'Account is disabled') {
      return res.status(401).json({ error: error.message });
    }
    next(error);
  }
});

export default router;
