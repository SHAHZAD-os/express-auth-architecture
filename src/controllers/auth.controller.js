import { registerUser as registerService, verifyOTPService, resendOtpService ,loginService,
  refreshTokenService,getAuthUserService
 } from '../services/auth.service.js';
import {
  forgotPasswordService,
  verifyResetOtpService,
  resetPasswordService,
} from '../services/auth.service.js'; // we'll add these
export const registerUser = async (req, res) => {
  return await registerService(req, res);
};

export const verifyOTP = async (req, res) => {
  return await verifyOTPService(req, res);
};

export const resendOtp = async (req, res) => {
  return await resendOtpService(req, res);
};

export const forgotPassword = async (req, res) => {
  return await forgotPasswordService(req, res);
};

export const verifyResetOTP = async (req, res) => {
  return await verifyResetOtpService(req, res);
};

export const resetPassword = async (req, res) => {
  return await resetPasswordService(req, res);
};
export const login=async(req,res)=>{
  return await loginService(req,res);
}

export const refreshToken = async (req, res) => {
  return await refreshTokenService(req, res);
}

export const getAuthUser = async (req, res) => {
  return await getAuthUserService(req, res);
}

