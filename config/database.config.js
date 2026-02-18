import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();
export const connectDB = async () => {
  try {
     console.log('MongoDB connecting successfully');
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1); // exit process if DB connection fails
  }
};
