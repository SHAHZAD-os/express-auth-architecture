import User from '../models/user.model.js';

export const findUserByEmail = (email) => User.findOne({ email });

export const createUser = (userData) => {
  const user = new User(userData);
  return user.save();
};

export const verifyUserByEmail = (email) => User.updateOne(
  { email },
  { $set: { isVerified: true } }
);


export const findUserByEmailWithPassword = async (email) => {
  return User.findOne({ email }).select('+password');
};
