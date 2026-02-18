import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

export const sendEmail = async (to, subject, text) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const info = await transporter.sendMail({
      from: `"Sandbox Test" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text
    });

    console.log(`Email sent: ${info.messageId}`);
  } catch (err) {
    console.error('Email sending error:', err.message);
  }
};
