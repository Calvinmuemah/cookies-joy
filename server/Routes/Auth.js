const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const Token = require('../Models/Token');
const generateTokens = require('../Utils/generateTokens');
const authMiddleware = require('../Middleware/authMiddleware');

const router = express.Router();


// REGISTER
router.post('/register', async (req, res) => {
  const { name, email, password, phone_number } = req.body;

  try {
    if (!name || !email || !password || !phone_number) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      phone_number,
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ msg: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ msg: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user._id);
    await Token.create({ userId: user._id, token: refreshToken });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({ accessToken });
  } catch (error) {
    console.error('Login route error:', error.message);
    res.status(500).json({ msg: 'Internal server error' });
  }
});

  

// REFRESH TOKEN
router.post('/refresh', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(403).json({ msg: 'No token provided' });
  
    const storedToken = await Token.findOne({ token: refreshToken });
    if (!storedToken) return res.status(403).json({ msg: 'Invalid token' });
  
    try {
      const payload = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
      const { accessToken, refreshToken: newRefresh } = generateTokens(payload.id);
  
      await Token.findOneAndDelete({ token: refreshToken });
      await Token.create({ userId: payload.id, token: newRefresh });
  
      // Set new refresh token in cookie again
      res.cookie('refreshToken', newRefresh, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
  
      res.json({ accessToken });
    } catch {
      res.status(401).json({ msg: 'Token expired or invalid' });
    }
  });
  

// LOGOUT
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  await Token.findOneAndDelete({ token: refreshToken });
  res.json({ msg: 'Logged out' });
});

// PROTECTED
router.get('/protected', authMiddleware, (req, res) => {
  res.json({ msg: 'Protected content', userId: req.userId });
});

module.exports = router;
