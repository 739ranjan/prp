import dotenv from 'dotenv';
import passport from 'passport';
import passportLocal, { IStrategyOptionsWithRequest } from 'passport-local';
import passportGoogle from 'passport-google-oauth20';
import GoogleTokenStrategy  from 'passport-google-id-token';
// import {VerifiedCallback} from 'passport';
import User, { IUser } from '../api/v1/user/user.model';
import Logger from '../lib/logger';
import { ICustomExpressRequest } from '../middlewares/currentUser.middleware';

dotenv.config();

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;

const LocalStrategy = passportLocal.Strategy;
const GoogleStrategy = passportGoogle.Strategy;

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((id, done) => {
  User.findOne({ _id: id }, (err: NativeError, user: IUser) => {
    done(null, user);
  });
});

const authFields: IStrategyOptionsWithRequest = {
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true,
};

/**
 * Login strategy
 */
passport.use(
  'login',
  new LocalStrategy(
    authFields,
    async (req: ICustomExpressRequest, email, password, cb) => {
      try {
        const user = await User.findOne({
          $or: [{ email }, { username: email.toLowerCase() }],
        }).exec();

        if (!user || !user.password) {
          return cb(null, false, { message: 'User not found.' });
        }

        const checkPassword = await user.comparePassword(password);

        if (!checkPassword) {
          return cb(null, false, { message: 'Incorrect email or password.' });
        }

        if (!user || !user.active) {
          return cb(null, false, { message: 'Account is deactivated.' });
        }

        user.lastLoginDate = new Date();
        await user.save();

        return cb(null, user, { message: 'Logged In Successfully' });
      } catch (err: unknown) {
        if (err instanceof Error) {
          Logger.debug(err);
          return cb(null, false, { message: err.message });
        }
      }
    }
  )
);

/**
 * Google OAuth strategy
 */
passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: <string>GOOGLE_CLIENT_ID,
      clientSecret: <string>GOOGLE_CLIENT_SECRET,
      callbackURL: `/api/v1/${process.env.SERVICE_NAME}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const username = profile.emails && profile?.emails[0]?.value;
        const email = profile.emails && profile?.emails[0]?.value;
        const pictureUrl = profile.photos && profile.photos[0].value;

        const googleUser = await User.findOne({
          'google.id': profile.id,
        }).exec();

        if (googleUser) {
          return done(null, googleUser, { statusCode: 200 });
        }

        const checkEmail = await User.checkExistingField('email', <string>email);

        const fieldsToUpdate = {
          pictureUrl,
          'google.id': profile.id,
          'google.sync': true,
          'google.tokens.accessToken': accessToken,
          'google.tokens.refreshToken': refreshToken,
        };

        if (checkEmail) {
          const user = await User.findByIdAndUpdate(
            checkEmail._id,
            fieldsToUpdate,
            { new: true }
          ).exec();

          return done(null, <IUser>user, { statusCode: 200 });
        }

        const userObj = new User({
          username,
          email,
          pictureUrl,
          password: accessToken,
          'google.id': profile.id,
          'google.sync': true,
          'google.tokens.accessToken': accessToken,
          'google.tokens.refreshToken': refreshToken,
        });

        const user = await userObj.save({ validateBeforeSave: false });

        return done(null, user, { statusCode: 201 });
      } catch (err: unknown) {
        if (err instanceof Error) {
          Logger.debug(err);
          return done(err, false);
        }
      }                 
    }
  )
);

/**
 * Google ID Token strategy (for backend validation)
 */
passport.use(
  new GoogleTokenStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID as string,
    },
    (parsedToken: any, googleId: string, done: (err: any, user: any) => void) => {
      try {
        const { payload } = parsedToken;
        if (!payload) {
          console.error('Invalid Google token: No payload found.');
          return done(new Error('No payload found in token'), null);
        }
 
        const user = {
          id: payload.sub,
          email: payload.email,
          name: payload.name,
          picture: payload.picture,
        };
 
        return done(null, user);
      } catch (error) {
        if (error instanceof Error) {
          // Safely access `error.message`
          console.error('Error validating Google token:', error.message);
        } else {
          console.error('Unexpected error validating Google token:', error);
        }
        return done(error, null);
      }
    }
  )
);
 

export default passport;
