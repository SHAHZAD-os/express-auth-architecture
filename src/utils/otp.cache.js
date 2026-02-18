const otpCache = new Map();

const MAX_ATTEMPTS = 5;
const LOCK_TIME = 600; // 10 mins

export const setOTP = (key, value, ttlSeconds = 300) => {
  const expiresAt = Date.now() + ttlSeconds * 1000;

  otpCache.set(key, { value, expiresAt });
console.log(`Set OTP for ${key}: ${value} (expires in ${ttlSeconds} seconds)`);
  setTimeout(() => otpCache.delete(key), ttlSeconds * 1000);
};

export const getOTP = (key) => {
  const data = otpCache.get(key);

  

  if (!data) return null;

  if (Date.now() > data.expiresAt) {
    otpCache.delete(key);
    return null;
  }

  return data.value;
};

export const deleteOTP = (key) => otpCache.delete(key);

export const isLocked = (context, email) => {
  return getOTP(`lock:${context}:${email}`);
};

export const recordFailedAttempt = (context, email) => {
  const attemptsKey = `attempts:${context}:${email}`;

  let attempts = getOTP(attemptsKey) || 0;
  attempts++;

  setOTP(attemptsKey, attempts, LOCK_TIME);

  if (attempts >= MAX_ATTEMPTS) {
    setOTP(`lock:${context}:${email}`, true, LOCK_TIME);
    deleteOTP(attemptsKey);
    return true; 
  }

  return false;
};

export const resetAttempts = (context, email) => {
  deleteOTP(`attempts:${context}:${email}`);
  deleteOTP(`lock:${context}:${email}`);
};

export default otpCache;
