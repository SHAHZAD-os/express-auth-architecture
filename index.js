import 'dotenv/config';
import express from 'express';
import { connectDB } from './config/database.config.js';
import authRoutes from './routes/auth.route.js';
import cookieParser from 'cookie-parser';




const app = express();
app.use(express.json({ strict: false }));
app.use(cookieParser());
const PORT = process.env.PORT || 5000;
// Connect to Database
connectDB();

app.use('/api', authRoutes);



app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
