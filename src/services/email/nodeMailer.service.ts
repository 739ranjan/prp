import nodemailer from 'nodemailer';
import {CustomError} from '../../errors';
import Logger from '../../lib/logger';
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});

interface MailOptions {
  from: string;
  to: string;
  subject: string;
  text: string;
}

const sendOtpEmail = async (email: string, otp: string): Promise<void> => {
  try {
    const mailOptions: MailOptions = {
      from: process.env.EMAIL as string,
      to: email,
      subject: 'User OTP',
      text: `Your OTP  is ${otp}. It is valid for the next 10 minutes.`,
    };
    await transporter.sendMail(mailOptions);
  } catch (error) {
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
    // here we are throwing an error instead of returning it
    throw error;
  }
};
export {sendOtpEmail};
