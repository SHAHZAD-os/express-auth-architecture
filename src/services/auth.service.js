import bcrypt from 'bcryptjs';
import { findUserByEmail, createUser, verifyUserByEmail, findUserByEmailWithPassword } from '../repositories/auth.repository.js';
import { generateOTP } from '../utils/otp.generate.js';
import { sendEmail } from '../utils/send.emails.js';
import { setOTP, getOTP, deleteOTP } from '../utils/otp.cache.js';
import { successResponse, errorResponse } from '../utils/response.js';
import User from '../models/user.model.js';
import { isLocked, recordFailedAttempt, resetAttempts } from '../utils/otp.attempts.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt.js';
// import { refreshCookieOptions } from '../utils/cookies.js';
import { storeRefreshToken, findRefreshTokenByUserIdAndHash, revokeRefreshToken, revokeAllUserRefreshTokens } from '../repositories/refreshToken.repository.js';
import { authCookieOptions, refreshCookieOptions } from '../utils/cookies.js';


export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await findUserByEmail(email);

    if (existingUser) {
      return errorResponse(res, 'Email already registered', 400);
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await createUser({
      name,
      email,
      password: hashedPassword
    });

    // Generate OTP
    const otp = generateOTP();
    setOTP(email, otp);

    await sendEmail(
      email,
      'Verify Your Account',
      `Your OTP is: ${otp}`
    );

    return successResponse(
      res,
      'User registered successfully. OTP sent to email.',
      201
    );

  } catch (error) {
    console.error(error);

    return errorResponse(
      res,
      error.message || 'Registration failed',
      500
    );
  }
};

export const verifyOTPService = async (req, res) => {
  try {
    const email = req.body.email;
    const { otp } = req.body;

    if (isLocked('verify', email)) {
      return errorResponse(res, 'Too many failed attempts. Try again later.', 429);
    }

    const cachedOTP = getOTP(email);
    console.log(`Verifying OTP for ${email}: provided ${otp}, cached ${cachedOTP}`);
    if (!cachedOTP) {
      return errorResponse(res, 'OTP expired or not found', 400);
    }

    if (String(cachedOTP) !== String(otp)) {
      const locked = recordFailedAttempt('verify', email);

      if (locked) {
        return errorResponse(res, 'Too many incorrect attempts. Locked for 10 minutes.', 429);
      }

      return errorResponse(res, 'Invalid OTP', 400);
    }

    await verifyUserByEmail(email);

    deleteOTP(email);
    resetAttempts('verify', email);

    return successResponse(res, 'Account verified successfully', 200);

  } catch (error) {
    console.error(error);
    return errorResponse(res, error.message || 'Verification failed', 500);
  }
};



export const resendOtpService = async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`Resend OTP requested for ${email}`);
    const user = await findUserByEmail(email);
    if (!user) {
      return errorResponse(res, 'Email not registered', 400);
    }
    if (user.isVerified) {
      return errorResponse(res, 'Account already verified', 400);
    }
    const otp = generateOTP();
    setOTP(email, otp);

    await sendEmail(
      email,
      'Resend OTP - Verify Your Account',
      `Your new OTP is: ${otp}`
    );
    return successResponse(res, 'OTP resent successfully', 200);
  } catch (error) {
    console.error(error);
    return errorResponse(res, error.message, 500);
  }
};

export const forgotPasswordService = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await findUserByEmail(email);
    if (!user) {
      return errorResponse(res, 'No account found with this email', 404);
    }

    const otp = generateOTP();
    setOTP(`reset:${email}`, otp, 600);

    await sendEmail(
      email,
      'Password Reset Request',
      `Use this OTP to reset your password: ${otp}\nThis OTP is valid for 10 minutes.`
    );

    return successResponse(res, 'Password reset OTP sent to your email', 200);
  } catch (error) {
    console.error(error);
    return errorResponse(res, 'Failed to send reset OTP', 500);
  }
};

export const verifyResetOtpService = async (req, res) => {
  try {
    const email = req.body.email.toLowerCase().trim();
    const { otp } = req.body;

    if (isLocked('reset', email)) {
      return errorResponse(res, 'Too many failed attempts. Try again later.', 429);
    }

    const cachedOTP = getOTP(`reset:${email}`);

    if (!cachedOTP) {
      return errorResponse(res, 'OTP expired or invalid', 400);
    }

    if (String(cachedOTP) !== String(otp)) {
      const locked = recordFailedAttempt('reset', email);

      if (locked) {
        return errorResponse(res, 'Too many incorrect attempts. Locked for 10 minutes.', 429);
      }

      return errorResponse(res, 'Incorrect OTP', 400);
    }

    deleteOTP(`reset:${email}`);
    resetAttempts('reset', email);

    setOTP(`reset-auth:${email}`, true, 900);

    return successResponse(res, 'OTP verified. You may now reset your password.', 200);

  } catch (error) {
    console.error(error);
    return errorResponse(res, 'OTP verification failed', 500);
  }
};


export const resetPasswordService = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const resetAuth = getOTP(`reset-auth:${email}`);

    if (!resetAuth) {
      return errorResponse(res, 'Session expired. Please verify OTP again.', 400);
    }

    const user = await findUserByEmail(email);

    if (!user) {
      return errorResponse(res, 'User not found', 404);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await User.updateOne(
      { email },
      { $set: { password: hashedPassword } }
    );

    deleteOTP(`reset-auth:${email}`);

    return successResponse(res, 'Password reset successfully', 200);

  } catch (error) {
    console.error(error);
    return errorResponse(res, 'Password reset failed', 500);
  }
};

export const loginService = async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const { password } = req.body;

    if (!email || !password) {
      return errorResponse(res, 'Email and password are required', 400);
    }

    const user = await findUserByEmailWithPassword(email);



    if (!user) {
      return errorResponse(res, 'Invalid credentials', 401);
    }

    if (!user.isVerified) {
      return errorResponse(res, 'Account not verified', 403);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return errorResponse(res, 'Invalid credentials', 401);
    }

    const payload = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role || 'user',
    };

    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await storeRefreshToken(user._id, refreshToken, expiresAt);

    res.cookie('accessToken', accessToken, authCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    return successResponse(res, 'Login successful', 200);

  } catch (error) {
    console.error(error);
    return errorResponse(res, 'Login failed', 500);
  }
};

export const refreshTokenService = async (req, res) => {
  try {
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      return errorResponse(res, 'Refresh token required', 401);
    }
    let decoded;
    try {
      decoded = verifyRefreshToken(oldRefreshToken);
    } catch {
      return errorResponse(res, 'Invalid or expired refresh token', 401);
    }
    const tokenRecord = await findRefreshTokenByUserIdAndHash(
      decoded.userId,
      oldRefreshToken
    );

    if (!tokenRecord) {
      return errorResponse(res, 'Refresh token not found or revoked', 401);
    }

    if (tokenRecord.revoked) {
      return errorResponse(res, 'Refresh token revoked', 401);
    }
    await revokeRefreshToken(tokenRecord);

    const payload = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };

    const newAccessToken = signAccessToken(payload);
    const newRefreshToken = signRefreshToken(payload);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await storeRefreshToken(decoded.userId, newRefreshToken, expiresAt);

    res.cookie('refreshToken', newRefreshToken, refreshCookieOptions);
    res.cookie('accessToken', newAccessToken, authCookieOptions);

    return successResponse(res, 'Tokens refreshed successfully', 200);
  } catch (err) {
    console.error(err);
    return errorResponse(res, 'Refresh failed', 500);
  }
};



export const getAuthUserService = async (req, res) => {
  try {
    return successResponse(res, 'Authenticated user retrieved successfully', 200, req.user);
  } catch (error) {
    console.error(error);
    return errorResponse(res, 'Failed to retrieve user info', 500);
  }
}






