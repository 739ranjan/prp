import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import mongoose, {
  HydratedDocument,
  Document,
  Model,
  Schema,
  Types,
} from 'mongoose';

import validator from 'validator';
import {CustomError} from '../../../errors';
import {apiRoles} from '../../config/roles.config';
import {promises} from 'dns';

dotenv.config();

if (!process.env.JWT_KEY) {
  throw new CustomError(
    404,
    'Please provide a JWT_KEY as global environment variable'
  );
}

const jwtKey = process.env.JWT_KEY;

/**
 * Define the Google Passport interface
 */

export interface IGooglePassport {
  id: string;
  sync: boolean;
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}

/**
 * define user messages interface
 */
export interface IUserMessages {
  title: string;
  body: string;
  type: string;
  read: boolean;
  firebaseMessageId: string;
}

/**
 * Define the User model...
 */
export interface IUser {
  // isModified(arg0: string): unknown;
  
  username: string;
  fullName: string;
  email: string;
  phoneNumber: number;
  password: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  otpPhone?: string;
  otpPhoneExpires?: Date;
  google: IGooglePassport;

  emailOTP: string;
  emailOtpExpiresAt: Date;

  // googleId:string;
  name: string;
  picture ?: string;
  isVerifiedEmail: boolean;
  isVerifiedPhone: boolean;
  OTPTokenEmail: string,
  OTPTokenEmailExpiresAt: Date,
  OTPTokenPhone: string,
  OTPTokenPhoneExpiresAt: Date,

  isVerified: boolean;
  role: string;
  active: boolean;
  employeeId: string;
  pictureUrl?: string;
  clientId: string;
  vendorId: string;
  deleted: boolean;
  pictureBlob: string;
  lastLoginDate: Date;
  notification: {
    fcmPermission: string;
    firebaseMessageToken: string;
  };
  messages: IUserMessages[];
  featureFlags?: {
    [key: string]: string;
  };
}

/**
 * Exporting methods for User
 */
export interface IUserMethods {
  toJSON(): Document<this>;
  comparePassword(password: string): Promise<boolean>;
  generateVerificationToken(): string;
  generatePasswordResetToken(): void;
  generateForgotOTP(): string;
  generateOTPandSave(): string;
  
}

/**
 * Create a new Model type that knows about Methods and stati and IUser...
 */
export interface IUserModel extends Model<IUser, {}, IUserMethods> {
  checkExistingField: (
    field: string,
    value: string
  ) => Promise<HydratedDocument<IUser, IUserMethods>>;
}

const MessageSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    body: {
      type: String,
      required: true,
      trim: true,
    },
    type: {
      type: String,
      required: true,
      trim: true,
    },
    read: {
      type: Boolean,
      default: false,
    },
    firebaseMessageId: {
      type: String,
    },
  },
  {
    toJSON: {
      virtuals: true,
      getters: true,
    },
    toObject: {
      virtuals: true,
      getters: true,
    },
    timestamps: true,
  }
);

const UserSchema = new Schema<IUser, IUserModel, IUserMethods>(
  {
    // username: {
    //   type: String,
    //   required: true,
    //   unique: true,
    //   lowercase: true,
    //   index: true,
    // },

    fullName: {
      type: String,
    },
    email: {
      type: String,
      required: [true, "Email can't be blank"],
      unique: true,
      lowercase: true,
      // index: true,
      // TODO: Re-enable the validation once migration is completed
      validate: [validator.isEmail, 'Please provide an email address'],
      match: [/\S+@\S+\.\S+/, 'is invalid'],
      // trim: true,
    },


    phoneNumber:{type: Number, unique: true, required: true, minlength: 10},
    password: {type: String, required: true, minlength: 5},

    resetPasswordToken: {
      type: String,
      required: false,
    },
    resetPasswordExpires: {
      type: Date,
      required: false,
    },
    otpPhone: {
      type: String,
      required: false,
     default: "",
    },
    otpPhoneExpires: {
      type: Date,
      required: false,
      default: null,
    },
    // google: {
    //   id: String,
    //   sync: {type: Boolean}, // authorization to sync with google
    //   tokens: {
    //     accessToken: String,
    //     refreshToken: String,
    //   },
    // },

   

    emailOTP: String,
    emailOtpExpiresAt: Date,


    // googleId: { type: String , unique: true, index: true }, // **NEW: Store Google ID (sub from token)**
    // isVerifiedEmail:{
    //   type: Boolean,
    //   default: false,
    // },
    // isVerifiedPhone:{
    //   type: Boolean,
    //   default: false,
    // },
    // **NEW: Last Login Date**
    lastLoginDate: {
      type: Date, // Store the last login time for the user
      default: null,
    },

    // **NEW: Profile Picture**
    pictureUrl: {
      type: String,
      trim: true,
    },

    isVerified:{
      type: Boolean,
      default: false,
    },
    name:{
      type: String,
    },
    picture:{
      type: String,
    },


    OTPTokenPhone: String,
    OTPTokenPhoneExpiresAt: Date,
    //   role: {
    //     type: String,
    //     enum: apiRoles,
    //     default: 'user',
    //   },
    //   active: {
    //     type: Boolean,
    //     default: true,
    //   },
    //   employeeId: {
    //     type: String,
    //   },
    //   pictureUrl: {
    //     type: String,
    //     trim: true,
    //     validate: {
    //       validator: (value: string) =>
    //         validator.isURL(value, {
    //           protocols: ['http', 'https', 'ftp'],
    //           require_tld: true,
    //           require_protocol: true,
    //         }),
    //       message: 'Must be a Valid URL',
    //     },
    //   },
    //   pictureBlob: {
    //     type: String,
    //   },
    //   lastLoginDate: {type: Date, required: false, default: null},
    //   notification: {
    //     fcmPermission: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     firebaseMessageToken: {type: String, trim: true, default: null},
    //   },
    //   messages: [MessageSchema],
    //   featureFlags: {
    //     allowSendEmail: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'granted',
    //     },
    //     allowSendSms: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'granted',
    //     },
    //     betaFeatures: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     darkMode: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     personalization: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     geolocationBased: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     security: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     payment: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //   },
    // },
    // {
    //   toJSON: {
    //     virtuals: true,
    //     getters: true,
    //   },
    //   toObject: {
    //     virtuals: true,
    //     getters: true,
    //   },

    // isVerified:{
    //   type: Boolean,
    //   default: false,
    // },

    //   role: {
    //     type: String,
    //     enum: apiRoles,
    //     default: 'user',
    //   },
    //   active: {
    //     type: Boolean,
    //     default: true,
    //   },
    //   employeeId: {
    //     type: String,
    //   },
    //   pictureUrl: {
    //     type: String,
    //     trim: true,
    //     validate: {
    //       validator: (value: string) =>
    //         validator.isURL(value, {
    //           protocols: ['http', 'https', 'ftp'],
    //           require_tld: true,
    //           require_protocol: true,
    //         }),
    //       message: 'Must be a Valid URL',
    //     },
    //   },
    //   pictureBlob: {
    //     type: String,
    //   },
    //   lastLoginDate: {type: Date, required: false, default: null},
    //   notification: {
    //     fcmPermission: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     firebaseMessageToken: {type: String, trim: true, default: null},
    //   },
    //   messages: [MessageSchema],
    //   featureFlags: {
    //     allowSendEmail: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'granted',
    //     },
    //     allowSendSms: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'granted',
    //     },
    //     betaFeatures: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     darkMode: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     personalization: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     geolocationBased: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     security: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //     payment: {
    //       type: String,
    //       enum: ['granted', 'denied', 'default'],
    //       default: 'default',
    //     },
    //   },
    // },
    // {
    //   toJSON: {
    //     virtuals: true,
    //     getters: true,
    //   },
    //   toObject: {
    //     virtuals: true,
    //     getters: true,
    //   },
  },
  {timestamps: true}
);

// UserSchema.index({username: 1, email: 1, googleId: 1});

/**
 * MONGOOSE MIDDLEWARE
 */
UserSchema.pre<HydratedDocument<IUser, IUserMethods>>(
  'save',
  async function (next) {
    if (!this.isModified('password')) return next();

    // const salt = await bcrypt.genSalt(10);
    // this.password = await bcrypt.hash(this.password, salt);
    next();
  }
);

/**
 * MONGOOSE METHODS
 */
UserSchema.methods.toJSON = function () {
  const userObj: any = this.toObject();
  userObj.id = userObj._id;

  delete userObj._id;
  delete userObj.password;
  delete userObj.__v;
  return userObj;
};

UserSchema.methods.comparePassword = async function (password: string) {
  console.log("current password", this.password);
  return bcrypt.compare(password, this.password);
};

UserSchema.methods.generateVerificationToken = function () {
  return jwt.sign(
    {
     // id: this._id,
      email: this.email,
      // active: this.active,
      // role: this.role,
      // employeeId: this.employeeId,
      // clientId: this.clientId,
      // vendorId: this.vendorId,
      // deleted: this.deleted,
      // featureFlags: this.featureFlags,
    },
    jwtKey,
    {
      expiresIn: '7d',
      // algorithm: 'RS256',
    }
  );
};

UserSchema.methods.generatePasswordResetToken = async function () {
  this.resetPasswordToken = crypto.randomBytes(22).toString('hex');
  this.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
};


// UserSchema.methods.generateForgotOTP = function () {
//   this.emailOTP = Math.floor(1000 + Math.random() * 9000).toString();
//   this.emailOtpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
//   return this.emailOTP;
// };

UserSchema.methods.generateOTPandSave = function () {
  // Generate a 6-digit OTP
  this.otpPhone = Math.floor(1000 + Math.random() * 9000).toString(); // Generates a random 4-digit number

  // Set OTP expiration time (e.g., 5 minutes from now)
  this.otpPhoneExpires = new Date(Date.now() + 5 * 60 * 1000); // Expires in 5 minutes

  return this.otpPhone; // Return the OTP for immediate use (optional)
};



/**
 * MONGOOSE STATIC METHODS
 */
UserSchema.statics.checkExistingField = async function (
  field: string,
  value: string
) {
  return this.findOne({[`${field}`]: value});
};

const User = mongoose.model<IUser, IUserModel>('User', UserSchema, 'users');

export default User;
