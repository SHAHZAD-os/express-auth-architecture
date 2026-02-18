// middleware/auth.middleware.js
import jwt from 'jsonwebtoken';
import { errorResponse } from '../utils/response.js';

export const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.split(' ')[1]
      : req.cookies?.accessToken;

    if (!token) {
      return errorResponse(res, 'Access token missing', 401);
    }

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // Only attach basic info from token
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };

    next();
  } catch (err) {
    return errorResponse(res, 'Invalid or expired access token', 401);
  }
};
