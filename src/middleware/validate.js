import { validationResult } from 'express-validator';
import { errorResponse } from '../utils/response.js';

export const validate = (validations) => async (req, res, next) => {
  await Promise.all(validations.map(validation => validation.run(req)));

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 'Validation failed', 400, errors.array());
  }
  next();
};