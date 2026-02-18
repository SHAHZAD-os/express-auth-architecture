import { body, validationResult } from 'express-validator';

export const registerValidation = [
    body('name')
        .trim()
        .notEmpty().withMessage('Name is required')
        .isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters'),

    body('email')
        .trim()
        .isEmail().withMessage('Please provide a valid email')
        .normalizeEmail(),

    body('password')
        .trim()
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

export const verifyOtpValidation = [
    body('email')
        .trim()
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail(),

    body('otp')
        .trim()
        .notEmpty().withMessage('OTP is required')
        .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
];

export const resendOtpValidation = [
    body('email')
        .trim()
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
];

// ── Forgot Password ───────────────────────────────────────
export const forgotPasswordValidation = [
    body('email')
        .trim()
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail(),
];

export const resetPasswordValidation = [
    body('email')
        .trim()
        .isEmail().withMessage('Valid email is required')
        .normalizeEmail(),

    body('otp')
        .trim()
        .notEmpty().withMessage('OTP is required')
        .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),

    body('newPassword')
        .trim()
        .isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
];