import express from 'express';
import {
  registerValidation,
  verifyOtpValidation,
  resendOtpValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  
} from '../src/validators/auth.validator.js';
import {
  registerUser,
  verifyOTP,
  resendOtp,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  login,
  refreshToken,
  getAuthUser
} from '../src/controllers/auth.controller.js';
import { validate } from '../src/middleware/validate.js';
import { authMiddleware } from '../src/middleware/auth.middleware.js';
// import {registerValidator} from '../src/validators/registeruser.validator.js';
const router = express.Router();

router.post('/register', validate(registerValidation), registerUser);
router.post('/verify-otp', validate(verifyOtpValidation), verifyOTP);
router.post('/resend-otp', validate(resendOtpValidation), resendOtp);

// Forgot password flow (3 steps)
router.post('/forgot-password', validate(forgotPasswordValidation), forgotPassword);
router.post('/verify-reset-otp', validate(verifyOtpValidation), verifyResetOTP);
router.post('/reset-password', validate(resetPasswordValidation), resetPassword);

router.post('/login', login);
router.post('/refresh-token', refreshToken);
router.get('/me', authMiddleware, getAuthUser);

export default router;