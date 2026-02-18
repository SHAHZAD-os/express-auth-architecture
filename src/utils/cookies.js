const isProduction = process.env.NODE_ENV === 'production';

export const authCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: process.env.COOKIE_SAME_SITE || 'lax',
  path: '/',
};

export const refreshCookieOptions = {
  ...authCookieOptions,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};
