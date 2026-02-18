import { getOTP, setOTP, deleteOTP } from './otp.cache.js';

const MAX_ATTEMPTS = 5;        
const LOCK_TIME = 600;         


export const isLocked = (type, email) => {
  const lock = getOTP(`lock:${type}:${email}`);
  return !!lock;
};

// Record a failed OTP attempt, return true if now locked
export const recordFailedAttempt = (type, email) => {
  const key = `attempts:${type}:${email}`;
  let attempts = getOTP(key) || 0;
  attempts += 1;

  if (attempts >= MAX_ATTEMPTS) {
    // Lock the user for LOCK_TIME seconds
    setOTP(`lock:${type}:${email}`, true, LOCK_TIME);
    deleteOTP(key); // reset attempts after locking
    return true;    // user is now locked
  }

  // Save attempts with TTL same as lock (or shorter)
  setOTP(key, attempts, LOCK_TIME);
  return false; // not locked yet
};

// Reset attempts after successful OTP verification
export const resetAttempts = (type, email) => {
  deleteOTP(`attempts:${type}:${email}`);
  deleteOTP(`lock:${type}:${email}`);
};
