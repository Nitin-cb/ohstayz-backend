// # User authentication and authorization
import userModel from '../models/userModel.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import twilio from 'twilio';

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// /api/auth/register
const register = async (req, res) => {
  const { phone, password, name } = req.body;

  try {
    const userExists = await userModel.findOne({ phone });
    if (userExists)
      return res
        .status(400)
        .json({ message: 'Phone number already registered' });

    const user = await userModel.create({ phone, password, name });
    res
      .status(201)
      .json({ message: 'User registered successfully', userId: user._id });
  } catch (error) {
    res
      .status(500)
      .json({ message: 'Registration failed', error: error.message });
  }
};

// /api/auth/login
const login = async (req, res) => {
  const { phone, password } = req.body;

  try {
    const user = await userModel.findOne({ phone });
    if (!user)
      return res
        .status(400)
        .json({ message: 'Invalid phone number or password' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch)
      return res
        .status(400)
        .json({ message: 'Invalid phone number or password' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
};

// /api/auth/forgot-password
const forgotPassword = async (req, res) => {
  const { phone } = req.body;

  try {
    const user = await userModel.findOne({ phone });
    if (!user)
      return res.status(400).json({ message: 'Phone number not found' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // Generate reset link
    const resetURL = `${req.protocol}://${req.get(
      'host'
    )}/api/auth/reset-password/${resetToken}`;

    // Send SMS
    const message = `Reset your password using this link: ${resetURL}`;
    await client.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone,
    });

    res
      .status(200)
      .json({ message: 'Password reset link sent to your phone via SMS' });
  } catch (error) {
    res.status(500).json({
      message: 'Failed to send reset password link',
      error: error.message,
    });
  }
};

// /api/auth/reset-password/:resetToken
const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  try {
    const user = await userModel.findOne({
      resetToken,
      resetTokenExpire: { $gt: Date.now() },
    });

    if (!user)
      return res.status(400).json({ message: 'Invalid or expired token' });

    user.password = newPassword;
    user.resetToken = null;
    user.resetTokenExpire = null;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    res
      .status(500)
      .json({ message: 'Password reset failed', error: error.message });
  }
};

// /api/auth/admin-login
const adminLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if email matches the admin email in environment variables
    if (email !== process.env.ADMIN_EMAIL) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials',
      });
    }

    // Check if the provided password matches the admin password
    if (password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials',
      });
    }

    // Create admin token
    const token = jwt.sign({ adminEmail: email }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.status(200).json({
      success: true,
      message: 'Admin login successful',
      token,
    });
  } catch (error) {
    console.error('Admin Login Error:', error);
    res.status(500).json({
      success: false,
      message: 'Admin login failed',
      error: error.message,
    });
  }
};

export { register, login, forgotPassword, resetPassword, adminLogin };
