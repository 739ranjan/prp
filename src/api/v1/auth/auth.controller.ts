import { NextFunction, Response, Request } from 'express';
import { IVerifyOptions } from 'passport-local';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ICustomExpressRequest } from '../../../middlewares/currentUser.middleware';
import createCookieFromToken from '../../../utils/createCookieFromToken.utils';
import { CustomError } from '../../../errors';
import Logger from '../../../lib/logger';
import passport from '../../../config/passport.config';
import User, {IUserMethods} from '../user/user.model';
import {sendResetPasswordToken} from '../../../services/email/sparkpost.service';
import {sendOtpEmail} from '../../../services/email/nodeMailer.service';
import {sendOtpSMS} from '../../../services/messaging/twilio.service';
import {randomInt} from 'crypto';
import {v4 as uuidv4} from 'uuid';
import {Message} from '@google-cloud/pubsub/build/src';
import {redis} from '../../../config/redis.config';
import {json} from 'stream/consumers';
import crypto from 'crypto';


function formatPhoneNumber(phoneNumber: string, countryCode: string = '+91'): string {
  // Ensure the phone number starts with the country code, remove spaces or dashes
  return phoneNumber.startsWith('+') ? phoneNumber : `${countryCode}${phoneNumber.replace(/\D/g, '')}`;
}

const generateHashedOtpTokens = async (
  otpEmail?: string,
  otpPhone?: string
): Promise<{otpEmailToken?: string; otpPhoneToken?: string}> => {
  if (!otpEmail && !otpPhone) {
    throw new Error('Both otpEmail and otpPhone cannot be undefined');
  }
 
  const otpEmailToken = otpEmail
    ? await bcryptjs.hash(otpEmail, 12)
    : undefined;
  const otpPhoneToken = otpPhone
    ? await bcryptjs.hash(otpPhone, 12)
    : undefined;
 
  return {otpEmailToken, otpPhoneToken};
};

const requestOTP = async (
  req: ICustomExpressRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const {email, phoneNumber} = req.body;

    //throw error if any one of email and phone number are present
    if (!email || !phoneNumber) {
      res.status(400).json({
        status: 'false',
        message: 'Please provide both email and phone number',
        data: null,
      });
      return;
    }

    //function to format phone number
    const formattedPhoneNumber = formatPhoneNumber(phoneNumber);
    const user = await User.findOne({
      $or: [{email: email}, {phoneNumber: phoneNumber}],
    });
    if (user) {
      res.status(404).json({
        status: 'fail',
        message: 'user already exists',
        data: null,
      });
      return;
    }
    let otpEmail;
    if (email) {
      otpEmail = randomInt(1000, 9999).toString();
      await sendOtpEmail(email, otpEmail);
    }
    let otpPhone;
    if (phoneNumber) {
      otpPhone = randomInt(1000, 9999).toString();
      await sendOtpSMS(formattedPhoneNumber, otpPhone);
    }
    const {otpEmailToken, otpPhoneToken} = await generateHashedOtpTokens(
      otpEmail,
      otpPhone
    );


    const sessionToken = uuidv4();
    const ttlSeconds = 600; // 10 minutes
    const redData = {
      otpEmailToken: otpEmailToken,
      otpPhoneToken: otpPhoneToken,
    };
    // Store OTP tokens in Redis with a short expiration
    await redis.del(sessionToken);
    await redis.set(sessionToken, JSON.stringify(redData));
    await redis.expire(sessionToken, ttlSeconds);

    // Return the session token to the client
    res.status(200).json({
      success: true,
      message: 'OTP sent to your email and Phone number',
      data: sessionToken,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: 'Signup failed',
      data: null,
    });
  }
};

 
/**
 * Verify OTP (For signup or login)
 */
 
const verifyOTP = async (
  req: ICustomExpressRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const { otpEmail, otpPhone} = req.body;
    const sessionToken = req.headers['authorization'];
    // Check if the sessionToken exists 
    if (!sessionToken) {
      return res.status(400).json({
        success: false,
        message: 'Session token not provided',
        data: null,
      });
    }
    const storedOtpData = await redis.get(sessionToken);
 console.log(storedOtpData)
    if (!storedOtpData || Object.keys(storedOtpData).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired session token',
        data: null,
      });
    }
 
    let parsedData;
    if (typeof storedOtpData === 'string') {
      parsedData = JSON.parse(storedOtpData);
    } else {
      console.error('Expected string but received:', typeof storedOtpData);
    }
 
    const otpEmailToken = parsedData.otpEmailToken;
    const otpPhoneToken = parsedData.otpPhoneToken;
 
    // Verify email OTP if provided
    if (otpEmail && otpEmailToken) {
      const isEmailOtpValid = await bcryptjs.compare(otpEmail, otpEmailToken);
      if (!isEmailOtpValid) {
        return res.status(400).json({
          success: 'fail',
          message: 'Invalid email OTP',
          data: null,
        });
      }
    }
 
    // Verify phone OTP if provided
    if (otpPhone && otpPhoneToken) {
      const isPhoneOtpValid = await bcryptjs.compare(otpPhone, otpPhoneToken);
      console.log(isPhoneOtpValid, "   ", otpPhone, "   ", otpPhoneToken);
      if (!isPhoneOtpValid) {
        return res.status(400).json({
          success: 'fail',
          message: 'Invalid phone OTP',
          data: null,
        });
      }
    }
 
    if (!process.env.JWT_KEY) {
      throw new CustomError(
        404,
        'Please provide a JWT_KEY as global environment variable'
      );
    }
    // Generate a verification token
    const verificationToken = jwt.sign({verify: true}, process.env.JWT_KEY, {
      expiresIn: 100000,
    });
 
    res.status(200).json({
      success: 'success',
      message: 'OTP verified successfully',
      data: verificationToken,
    });
  } catch (error) {
    console.log(error);
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
  }
};


// const verifyLoginOTPSMS = async (
//   req: ICustomExpressRequest,
//   res: Response,
//   next: NextFunction
// ) => {
//   const { otp } = req.body;
//   const {phoneNumber} = req.params;
//   try {
//     // Find the user by email
//     const user = await User.findOne({ phoneNumber });
//     if (!user) {
//       return res.status(404).json({ status: false, message: 'User not found' });
//     }
//     if (user) {
//      console.log("user found successfully")
//     }

//     // Check if OTP matches and hasn't expired
//     const isOtpValid = user.otpPhone === otp;
//     console.log(user);
//     console.log(isOtpValid,"   ",otp,"   ",user.otpPhone );
//     if (!isOtpValid) {
//       return res.status(401).json({ status: false, message: 'Invalid or expired OTP' });
//     }

//     // Generate a JWT token
//     const token = createCookieFromToken(user, 201, req, res);

//     // Clear OTP after successful verification
//     // user.otpPhone = undefined;
//     // user.otpPhoneExpires = undefined;
//     // await user.save();

//     return res.status(200).json({
//       status: true,
//       message: 'OTP verified successfully',
//       data: token,
//     });
//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({ status: false, message: error });
//   }
// };

/**
 * Signup Local strategy
 * @param req
 * @param res
 * @param next
 */
 
const signup = async (
  req: ICustomExpressRequest,
  res: Response,
  next: NextFunction
) => {
  console.log("data received");
  const { fullName, email, phoneNumber, password, confirmPassword } = req.body;
      try {
       

          // Basic validations
          if (!fullName) return res.status(400).json({ status: false,
            message: 'Full name is required', data: null, });
            if (!email || !phoneNumber) return res.status(400).json({status: false,
              message: 'Both email and phone are required', data: null, });
              if (password !== confirmPassword) return res.status(400).json({status: false,
                error: 'Passwords do not match', data: null, });
                
                //   //check if user exist already
                //   const userExist = await User.findOne({
                //   $or: [{email: email}, {phone: email}],
                // });
                // if (userExist) {
                //   res.status(404).json({
                //     status: 'fail',
                //     message: 'user already exist',
                //     data: null,
                //   });
                // }

                //hashing the password
                const hashedPassword = await bcryptjs.hash(password, 10);
                
                const user = new User({
                  email,
                  // password,
                  password: hashedPassword,
                  fullName,
                  phoneNumber,
                });
                
                await user.save();
                
                //sign jwt token and set it in cookie
                const token = createCookieFromToken(user, 201, req, res);
                
                res.status(201).json({
                  status: true,
                  message: 'User created successfully',
                  token: token,
                });
              
   }catch (error) {
    res.status(400).json({status: false, message: 'signup failed', data: error});
  }
}
 
 
/**
 * Login Local strategy
 * @param req
 * @param res
 * @param next
 */
 

const login = async(
    req: ICustomExpressRequest,
    res: Response,
    next: NextFunction
  ) => {
    const { email, password, phoneNumber} = req.body;
  
    try {
      // 1. Email and Password Login
      if (email && password) {
        const user = await User.findOne({ email });
        if (!user) {
          return res.status(400).json({ status: false, message: 'User not found', data: null, });
        }
       
       // const hashedPass =await bcryptjs.hash(password, 10);
        console.log(password, "," , "  ,  ", user.password);
       const isPasswordMatch = await user.comparePassword(password);
      //  const isPasswordMatch = password === user.password;
        console.log(isPasswordMatch);
        if (!isPasswordMatch) {
          return res.status(401).json({ status: false, message: 'Invalid password', data:null, });
        }
  
        // generate a signed json web token with the contents of user
        // object and return it in the response
        const authToken=  createCookieFromToken(user, 200, req, res);
  
        return res.status(200).json({
          status: true,
          message: 'Login successful with email and password',
          data: authToken,
        });
      }
  
      // 2. Mobile OTP Login
      


      if (phoneNumber) {
        const user = await User.findOne({ phoneNumber });
        if (!user) {
          return res.status(400).json({ status: false, message: 'User with this phone number not found', data:null, });
        }
        if (user) {
         console.log("user found with this phone number", phoneNumber)
        }
  
       //if phone number present, send otp to phoneNumber and save otp to DB for further verification
      //  const otp = user.generateOTPandSave()
      //  console.log("otp is : " ,otp)
      // //  const otp = "1234";
      //  const formattedPhoneNumber = formatPhoneNumber(phoneNumber); // , +917462089970

      //  await sendOtpSMS(formattedPhoneNumber, otp);

          //function to format phone number
          const formattedPhoneNumber = formatPhoneNumber(phoneNumber);
           const otpPhone = randomInt(1000, 9999).toString();
            await sendOtpSMS(formattedPhoneNumber, otpPhone);
          
          const { otpPhoneToken} = await generateHashedOtpTokens(
            otpPhone
          );


          const sessionToken = uuidv4();
          const ttlSeconds = 600; // 10 minutes
          const redData = {
            otpPhoneToken: otpPhoneToken,
          };
          // Store OTP tokens in Redis with a short expiration
          await redis.del(sessionToken);
          await redis.set(sessionToken, JSON.stringify(redData));
          await redis.expire(sessionToken, ttlSeconds);
              return res.status(200).json({
                status: true,
                message: 'OTP sent successfully to phone number',
                data: sessionToken,
              }); 
          }
  } catch (error) {
      console.error(error);
      return res.status(500).json({ status: false, message: error, data: null, });
    }
  };
 
/**
 * Logout
 * @param req
 * @param res
 * @param next
 */
const logout = (req: ICustomExpressRequest, res: Response, next: NextFunction) => {
  try {
    res.clearCookie('jwt');
    res.clearCookie('connect.sid');
    req.session.destroy(error => {
      if (error) {
        return next(error);
      }
      return res.status(200).json({
        status: 'success',
        message: 'You have successfully logged out',
      });
    });
  } catch (error) {
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
  }
};
 
/**
 * Recover password
 * @param req
 * @param res
 */
const recoverPassword = async (req: ICustomExpressRequest, res: Response) => {
  try {
    const {email} = req.body;
    const user = await User.findOne({email}).exec();
 
    if (!user) {
      return res.status(404).json({
        status: 'error',
        error: {
          status: 'error',
          message: 'User not found',
          data: null,
        },
      });
    }
 
    // Destroy session and remove any cookie
    req.session.destroy(() => {
      res.clearCookie('jwt');
    });
 
    res.clearCookie('jwt');
 
    // sent otp to email
    let otpEmail;
    if (email) {
      otpEmail = randomInt(1000, 9999).toString();
      await sendOtpEmail(email, otpEmail);
    }
 
    const {otpEmailToken} = await generateHashedOtpTokens(otpEmail);
    const sessionToken = uuidv4();
    const ttlSeconds = 600; // 10 minutes
    const redData = {
      otpEmailToken: otpEmailToken,
    };
    // Store OTP tokens in Redis with a short expiration
    await redis.del(sessionToken);
    await redis.set(sessionToken, JSON.stringify(redData));
    await redis.expire(sessionToken, ttlSeconds);
    // const sendEmail = await sendResetPasswordToken(
    //   user.email as string,
    //   user.resetPasswordToken as string
    // );
    res.status(200).json({
      status: 'success',
      message: `A reset email has been sent to ${user.email}.`,
      data: sessionToken,
    });
  } catch (error) {
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    } else {
      res.status(500).json({
        status: 'error',
        message: `Email could not be sent, ${error}`,
        data: null ,
      });
    }
  }
};
 
/**
 * Reset password
 * @param req
 * @param res
 * @param next
 */

const resetPassword = async (
  req: ICustomExpressRequest,
  res: Response,
  next: NextFunction
) => {

  try {
    const {password, confirmPassword} = req.body;
    const {email} = req.params;
 
    if (password !== confirmPassword) {
      return res.status(400).json({status: false, message: 'Passwords do not match', data: null,});
    }
 
    const user = await User.findOne({email});
    if (!user) {
      return res.status(404).json({status: false, message: 'User not found', data: null,});
    }
 
    const hashedPassword = await bcryptjs.hash(password, 10);
    user.password = hashedPassword;
    await user.save();
 
    const token = createCookieFromToken(user, 201, req, res);
 
    res.status(200).json({
      status: 'success',
      message: 'Password successfully updated',
      data: token,
    });
  } catch (error) {
    res.status(500).json({status: false, message: 'Failed to reset password', data: null,});
  }
};
 
/**
 * Return authenticated user
 * @param req
 * @param res
 */
const returnUserLogged = async (req: ICustomExpressRequest, res: Response) => {
  try {
    if (!req.currentUser) {
      return res.status(401).json({
        status: 'error',
        error: {
          message: 'If you can see this message, there is something wrong with authentication',
        },
      });
    }
 
    const user = await User.findById(req.currentUser?.id);
 
    res.status(200).json({
      status: 'success',
      message: 'User logged retrieved',
      data: {
        user,
      },
    });
  } catch (error) {
    Logger.error(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
  }
};
 
/**
 * Google Login
 * @param req
 * @param res
 */
const googleLogin = async (req: ICustomExpressRequest, res: Response) => {
  try {
    const user = req.user as IUserMethods;
 
    createCookieFromToken(user, 201, req, res);
  } catch (error) {
    Logger.debug(error);
    if (error instanceof CustomError) {
      throw new CustomError(error.statusCode, error.message);
    }
  }
};
 
/**
 * Verify Google Token
 * @param req
 * @param res
 */
interface GoogleUser {
  id: string;
  email: string;
  name: string;
  picture: string;
}
 

const authenticateGoogleToken = (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('google-id-token', { session: false }, (err: any, user: any, info: any) => {
    if (err) {
      // If an error occurred during authentication (including JWT errors)
      console.error('Authentication failed:', err);
      return res.status(500).json({
        status: 'error',
        message: 'Authentication failed.',
        error: err.message || err,
      });
    }
 
    if (!user) {
      // (invalid token)
      console.error('Invalid Google token');
      return res.status(401).json({
        status: 'error',
        message: 'Invalid token.',
        error: info || 'Invalid Google token.',
        // error: 'Invalid Google token.',
      });
    }
 
    // If the token is valid and the user is authenticated
    req.user = user;
    return next();
  })(req, res, next);
};

const verifyToken = async (req: Request, res: Response) => {
  try {
    const googleUser = req.user as GoogleUser;
 
    if (!googleUser) {
      console.error('Invalid Google token: No user found.');
      return res.status(401).json({
        status: 'error',
        message: 'Invalid Google token',
        data: null,
      });
    }
 
    let existingUser = await User.findOne({ email: googleUser.email });
 
    if (!existingUser) {
      existingUser = new User({
        googleId: googleUser.id,
        email: googleUser.email,
        name: googleUser.name,
        picture: googleUser.picture,
      });
      await existingUser.save();
    }
 
    const accessToken = jwt.sign(
      { id: existingUser.id, email: existingUser.email },
      process.env.JWT_SECRET as string,
      { expiresIn: '1h' }
    );
 
 
    const responsePayload = {
      // sessionToken: `session-${existingUser.id}-${Date.now()}`,
      jwtToken: accessToken, // Include the JWT in the response
      user: {
        id: existingUser.id,
        email: existingUser.email,
        name: existingUser.name,
        picture: existingUser.picture,
      },
    };
 
 
    res.status(200).json({
      status: 'success',
      message: 'Token verified successfully',
      data: responsePayload,
    });
  } catch (error: any) {
    console.error('Error during token verification:', error);
 
    if (error instanceof jwt.JsonWebTokenError) {
      // Catch JWT errors like invalid signature
      return res.status(401).json({
        status: 'error',
        message: 'Invalid Google token',
        error: { message: error.message, trace: error },
      });
    }
 
    console.error('Unexpected error verifying token:', error);
    res.status(500).json({
      status: 'error',
      message: 'An unexpected error occurred',
      error: { message: error.message, trace: error },
    });
  }
};
 
// const authenticateGoogleToken=passport.authenticate('google-token',{session:false});
 
export {
  requestOTP,
  verifyOTP,
  signup,
  login,
  logout,
  recoverPassword,
  resetPassword,
  returnUserLogged,
  googleLogin,
  verifyToken,
  authenticateGoogleToken,
 
};


