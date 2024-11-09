import express from 'express';
import passport from '../../../config/passport.config';
import {
  recoverPasswordApiLimiter,
  resetPasswordApiLimiter,
} from '../../../middlewares/apiRateLimit.middleware';
import catchAsyncHandler from '../../../middlewares/catchAsyncHandler.middleware';

import {requireAuthenticationMiddleware} from '../../../middlewares/requireAuthentication.middleware';
//import currentuser middleware token form middleware
import {currentUserMiddleware} from '../../../middlewares/currentUser.middleware';

import {
  googleLogin,
  login,
  logout,
  recoverPassword,
  requestOTP,
  resetPassword,
  returnUserLogged,
  signup,
  verifyOTP,
  verifyToken,
  authenticateGoogleToken,
} from './auth.controller';

const authRouter = express.Router();

authRouter.post('/requestOTP', catchAsyncHandler(requestOTP));
authRouter.post('/verifyOTP', catchAsyncHandler(verifyOTP));


// authRouter.post('/verifyLoginOTPSMS/:phoneNumber', catchAsyncHandler(verifyLoginOTPSMS));
authRouter.post('/signup', currentUserMiddleware, catchAsyncHandler(signup));
authRouter.post('/login', catchAsyncHandler(login));
authRouter.post('/logout', catchAsyncHandler(logout));
authRouter.post(
  '/recover-password',
  recoverPasswordApiLimiter,
  catchAsyncHandler(recoverPassword)
);
authRouter.post(
  '/reset-password/:email',
  resetPasswordApiLimiter,currentUserMiddleware,
  catchAsyncHandler(resetPassword)
);
authRouter.get(
  '/me',
  requireAuthenticationMiddleware,
  catchAsyncHandler(returnUserLogged)
);

/**
 * Social Authentication: Google
 */
authRouter.get(
  '/google',
  passport.authenticate('google', {
    session: false,
    scope: ['profile', 'email'],
  })
);
// callback route for Google authentication
authRouter.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    scope: ['profile', 'email'],
  }),
  googleLogin
);

// google id token verification route
authRouter.post(
  '/verify-token',
 authenticateGoogleToken,
  catchAsyncHandler(verifyToken)
);

export default authRouter;
