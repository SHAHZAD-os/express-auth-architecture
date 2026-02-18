export const successResponse = (res, message = 'Success', status = 200, data = {}) => {
  return res.status(status).json({
    success: true,
    message,
    data
  });
};

export const errorResponse = (res, message = 'Error', status = 500, errors = null) => {
  return res.status(status).json({
    success: false,
    message,
    errors
  });
};
