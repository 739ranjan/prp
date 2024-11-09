import {Twilio} from 'twilio';
import {CustomError} from '../../errors';
import Logger from '../../lib/logger';

/**
 * Send an OTP via SMS using Twilio
 * @param phoneNumber -  (include country code, e.g., +91 for India)
 */

const sendOtpSMS = async (phone: string, otp: string): Promise<void> => {
  try {
    const accountSid = process.env.TWILIO_ACCOUNT_SID; // Twilio Account SID
    const authToken = process.env.TWILIO_AUTH_TOKEN; // Twilio Auth Token
    const client = new Twilio(accountSid, authToken);
    const message = await client.messages.create({
      body: `Your OTP is: ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone,
    });
    console.log(`OTP sent to ${phone}: ${message.sid}`);
  } catch (error) {
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
    // here we are throwing an error instead of returning it
    throw error;
  }
};

export {sendOtpSMS};
