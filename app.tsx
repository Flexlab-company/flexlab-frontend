// src/services/auth.service.ts
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { User, UserDocument } from '../schemas/user.schema';
import { EmailService } from './email.service';
import { Response } from 'express';
import { AllowedEmail, AllowedEmailDocument } from '../schemas/allowed-email.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(AllowedEmail.name) private allowedEmailModel: Model<AllowedEmailDocument>,
    private emailService: EmailService,
  ) {}

  /** JWT_SECRET is required at bootstrap (main.ts); this throws if missing (e.g. in tests). */
  private getJwtSecret(): string {
    const secret = process.env.JWT_SECRET?.trim();
    if (!secret) {
      throw new HttpException('Server configuration error: JWT_SECRET is required', HttpStatus.INTERNAL_SERVER_ERROR);
    }
    return secret;
  }

  // 🔐 SIGNUP FLOW with whitelist + verification + resend
  async signup(email: string, password: string) {
    try {
      const normalizedEmail = email.toLowerCase().trim();

      // 0) Check if email is allowed (whitelist in `emails` collection)
      const allowed = await this.allowedEmailModel.findOne({ email: normalizedEmail });
      if (!allowed) {
  throw new HttpException(
    {
      success: false,
      code: 'EMAIL_NOT_ALLOWED',
      message: 'You are not allowed to sign up with this email. Please contact support.',
    },
    HttpStatus.FORBIDDEN,
  );
}


      // 1) Check if user already exists in `users` collection
      const existingUser = await this.userModel.findOne({ email: normalizedEmail });

      // 👉 CASE 1: User already exists AND emailVerified = true
      if (existingUser && existingUser.emailVerified) {
  throw new HttpException(
    {
      success: false,
      code: 'USER_ALREADY_EXISTS',
      message: 'User already exists. Please sign in.',
    },
    HttpStatus.CONFLICT,
  );
}


      // 👉 CASE 2: User exists BUT email is NOT verified → resend verification code
      if (existingUser && !existingUser.emailVerified) {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

        existingUser.verificationCode = verificationCode;
        existingUser.verificationCodeExpiry = verificationCodeExpiry;
        existingUser.skipNextLoginOtp = true;
        await existingUser.save();

        await this.emailService.sendVerificationEmail(
          normalizedEmail,
          verificationCode,
          `${existingUser._id}`,
        );

        return {
          success: true,
          message:
            'Account already exists but is not verified. A new verification code has been sent to your email.',
          userId: (existingUser._id as any).toString(),
        };
      }

      // 👉 CASE 3: User does NOT exist → create new user + send verification email
      const hashedPassword = await bcrypt.hash(password, 10);

      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

      const user = new this.userModel({
        email: normalizedEmail,
        password: hashedPassword,
        emailVerified: false,
        identityVerified: false,
        verificationCode,
        verificationCodeExpiry,
        skipNextLoginOtp: true,

      });

      await user.save();

      await this.emailService.sendVerificationEmail(
        normalizedEmail,
        verificationCode,
        `${user._id}`,
      );

      return {
        success: true,
        message: 'User created successfully. Please check your email for the verification code.',
        userId: (user._id as any).toString(),
      };
    } catch (error) {
  const status =
    (error as any)?.status ??
    (error as any)?.response?.statusCode ??
    HttpStatus.INTERNAL_SERVER_ERROR;

  const response =
    (error as any)?.response ??
    {
      success: false,
      code: 'INTERNAL_ERROR',
      message: (error as any)?.message || 'Something went wrong',
    };

  throw new HttpException(response, status);
}

}

  // ✅ VERIFY EMAIL by 6-digit code + optional userId
  async verifyEmail(code: string, userId?: string) {
    try {
      console.log("🔍 [VERIFY EMAIL] request:", { code, userId });

      const query: any = { verificationCode: code };

      if (userId) {
        query._id = userId;
      }

      const user = await this.userModel.findOne(query) as UserDocument | null;

      console.log("🔍 [VERIFY EMAIL] user from DB:", user?._id?.toString() || null);

      if (
        !user ||
        !user.verificationCodeExpiry ||
        new Date() > user.verificationCodeExpiry
      ) {
        throw new HttpException(
          'Invalid or expired verification code',
          HttpStatus.BAD_REQUEST,
        );
      }

      if (user.emailVerified) {
        throw new HttpException('Email already verified', HttpStatus.BAD_REQUEST);
      }

      user.emailVerified = true;
      user.verificationCode = null;
      user.verificationCodeExpiry = null;
      // So reset skipNextLoginOtp to false so that next manual signin will require OTP
      user.skipNextLoginOtp = false;

      await user.save();

      console.log("✅ [VERIFY EMAIL] Email verified for:", user.email);

      // ✅ Automatically sign in the user after email verification (like first time login)
      // Generate JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        this.getJwtSecret(),
        { expiresIn: '24h' },
      );

      return {
        success: true,
        message: 'Email verified and user signed successfully',
        token, // Return token for automatic signin
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
          isProfileComplete: user.isProfileComplete,
          identityVerified: user.identityVerified,
          hasValidPaymentMethod: user.hasValidPaymentMethod,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        skipOtp: true, // Frontend ko bataye ke OTP skip kiya gaya (for this auto-signin only)
      };
    } catch (error) {
      console.error("❌ [VERIFY EMAIL ERROR]:", error);
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // 🔐 SIGNIN – normal (admin ya jahan direct login chahiye)
  async signin(email: string, password: string) {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      const user = await this.userModel.findOne({ email: normalizedEmail });

      if (!user) {
  throw new HttpException(
    {
      success: false,
      code: 'ACCOUNT_NOT_FOUND',
      message: 'Account does not exist. Please sign up first.',
    },
    HttpStatus.NOT_FOUND,
  );
}

const isPasswordValid = await bcrypt.compare(password, user.password);
if (!isPasswordValid) {
  throw new HttpException(
    {
      success: false,
      code: 'INVALID_PASSWORD',
      message: 'Incorrect password. Please try again.',
    },
    HttpStatus.UNAUTHORIZED,
  );
}


      // Email must be verified before login
      if (!user.emailVerified) {
  // ✅ new verification code for email verification
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 min

  user.verificationCode = verificationCode;
  user.verificationCodeExpiry = verificationCodeExpiry;
  await user.save();

  await this.emailService.sendVerificationEmail(
    user.email,
    verificationCode,
    `${user._id}`,
  );

  // ✅ IMPORTANT: throw structured error so frontend can redirect
  throw new HttpException(
    {
      success: false,
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Your email is not verified. We’ve sent you a new verification code. Please check your inbox.',
      userId: `${user._id}`,
      email: user.email,
    },
    HttpStatus.UNAUTHORIZED,
  );
}


      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        this.getJwtSecret(),
        { expiresIn: '24h' },
      );

      return {
        success: true,
        message: 'Signed in successfully',
        token,
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
          isProfileComplete: user.isProfileComplete,
          identityVerified: user.identityVerified,
          hasValidPaymentMethod: user.hasValidPaymentMethod,
          firstName: user.firstName,
          lastName: user.lastName,
        },
      };
    } catch (error) {
  const status =
    (error as any)?.status ??
    (error as any)?.response?.statusCode ??
    HttpStatus.INTERNAL_SERVER_ERROR;

  const response =
    (error as any)?.response ??
    {
      success: false,
      code: 'INTERNAL_ERROR',
      message: (error as any)?.message || 'Something went wrong',
    };

  throw new HttpException(response, status);
}

  }

  // 🔐 NEW: SIGNIN INIT (OTP bhejna)
  async signinInit(email: string, password: string) {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      const user = await this.userModel.findOne({ email: normalizedEmail });

      if (!user) {
  throw new HttpException(
    {
      success: false,
      code: 'ACCOUNT_NOT_FOUND',
      message: 'Account does not exist. Please sign up first.',
    },
    HttpStatus.NOT_FOUND,
  );
}

const isPasswordValid = await bcrypt.compare(password, user.password);
if (!isPasswordValid) {
  throw new HttpException(
    {
      success: false,
      code: 'INVALID_PASSWORD',
      message: 'Incorrect password. Please try again.',
    },
    HttpStatus.UNAUTHORIZED,
  );
}


     if (!user.emailVerified) {
  // ✅ new verification code for email verification
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 min

  user.verificationCode = verificationCode;
  user.verificationCodeExpiry = verificationCodeExpiry;
  await user.save();

  await this.emailService.sendVerificationEmail(
    user.email,
    verificationCode,
    `${user._id}`,
  );

  // ✅ IMPORTANT: throw structured error so frontend can redirect
  throw new HttpException(
    {
      success: false,
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Your email is not verified. We’ve sent you a new verification code. Please check your inbox.',
      userId: `${user._id}`,
      email: user.email,
    },
    HttpStatus.UNAUTHORIZED,
  );
}
// ✅ First login after signup/verification → skip OTP once
if (user.skipNextLoginOtp) {
  user.skipNextLoginOtp = false;
  user.loginOtpCode = null;
  user.loginOtpExpiry = null;
  await user.save();

  const token = jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    this.getJwtSecret(),
    { expiresIn: '24h' },
  );

  return {
    success: true,
    message: 'Signed in successfully',
    token,
    user: {
      _id: user._id,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
      isProfileComplete: user.isProfileComplete,
      identityVerified: user.identityVerified,
      hasValidPaymentMethod: user.hasValidPaymentMethod,
      firstName: user.firstName,
      lastName: user.lastName,
    },
    skipOtp: true, // optional: frontend info
  };
}


      const loginOtpCode = Math.floor(100000 + Math.random() * 900000).toString();

      const loginOtpExpiry = new Date(Date.now() + 60 * 1000); // 60 seconds

      user.loginOtpCode = loginOtpCode;
      user.loginOtpExpiry = loginOtpExpiry;
      await user.save();

      await this.emailService.sendLoginOtpEmail(user.email, loginOtpCode);

      return {
        success: true,
        message: 'Login OTP sent to your email',
        userId: (user._id as any).toString(),
      };
    } catch (error) {
      const status =
        (error as any)?.status ??
        (error as any)?.response?.statusCode ??
        HttpStatus.INTERNAL_SERVER_ERROR;

      const response =
        (error as any)?.response ??
        {
          success: false,
          code: 'INTERNAL_ERROR',
          message: (error as any)?.message || 'Something went wrong',
        };

      throw new HttpException(response, status);
    }
  }
  // 🔐 NEW: SIGNIN VERIFY OTP
  async verifySigninOtp(email: string, code: string) {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      const user = await this.userModel.findOne({ email: normalizedEmail }) as UserDocument | null;

      if (!user) {
        throw new HttpException('Invalid email or OTP', HttpStatus.BAD_REQUEST);
      }

      if (
        !user.loginOtpCode ||
        !user.loginOtpExpiry ||
        user.loginOtpCode !== code ||
        new Date() > user.loginOtpExpiry
      ) {
        throw new HttpException('Invalid or expired OTP', HttpStatus.BAD_REQUEST);
      }
if (!user.emailVerified) {
  // ✅ new verification code for email verification
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 min

  user.verificationCode = verificationCode;
  user.verificationCodeExpiry = verificationCodeExpiry;
  await user.save();

  await this.emailService.sendVerificationEmail(
    user.email,
    verificationCode,
    `${user._id}`,
  );

  // ✅ IMPORTANT: throw structured error so frontend can redirect
  throw new HttpException(
    {
      success: false,
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Your email is not verified. We’ve sent you a new verification code. Please check your inbox.',
      userId: `${user._id}`,
      email: user.email,
    },
    HttpStatus.UNAUTHORIZED,
  );
}


      user.loginOtpCode = null;
      user.loginOtpExpiry = null;
      await user.save();

      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        this.getJwtSecret(),
        { expiresIn: '24h' },
      );

      return {
        success: true,
        message: 'Signed in successfully',
        token,
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
          isProfileComplete: user.isProfileComplete,
          identityVerified: user.identityVerified,
          hasValidPaymentMethod: user.hasValidPaymentMethod,
          firstName: user.firstName,
          lastName: user.lastName,
        },
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
async resendSigninOtp(email: string) {
  try {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.userModel.findOne({ email: normalizedEmail });

    if (!user) {
      throw new HttpException('Invalid email', HttpStatus.BAD_REQUEST);
    }

if (!user.emailVerified) {
  // ✅ new verification code for email verification
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 min

  user.verificationCode = verificationCode;
  user.verificationCodeExpiry = verificationCodeExpiry;
  await user.save();

  await this.emailService.sendVerificationEmail(
    user.email,
    verificationCode,
    `${user._id}`,
  );

  // ✅ IMPORTANT: throw structured error so frontend can redirect
  throw new HttpException(
    {
      success: false,
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Your email is not verified. We’ve sent you a new verification code. Please check your inbox.',
      userId: `${user._id}`,
      email: user.email,
    },
    HttpStatus.UNAUTHORIZED,
  );
}


    const loginOtpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const loginOtpExpiry = new Date(Date.now() + 60 * 1000); // ✅ 60 seconds

    user.loginOtpCode = loginOtpCode;
    user.loginOtpExpiry = loginOtpExpiry;
    await user.save();

    await this.emailService.sendLoginOtpEmail(user.email, loginOtpCode);

    return {
      success: true,
      message: 'Login OTP resent to your email',
       expiresInSeconds: 60,
  expiresAt: loginOtpExpiry.toISOString(),
    };
  } catch (error) {
    throw new HttpException(
      (error as any).message || 'Something went wrong',
      (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}

  // Send password reset code
  async sendPasswordResetCode(email: string) {
    try {
      console.log('🔍 Finding user for password reset:', email);
      const user = await this.userModel.findOne({ email });
      if (!user) {
        console.log('⚠️ User not found for reset, but returning success for security');
        return {
          success: true,
          message: 'If the email is registered, a reset code will be sent.',
        };
      }

      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
      const resetCodeExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      console.log('💾 Saving reset code for user:', user._id);
      user.passwordResetCode = resetCode;
      user.passwordResetExpiry = resetCodeExpiry;
      await user.save();

      console.log('📧 Sending password reset email...');
      try {
        await this.emailService.sendPasswordResetEmail(email, resetCode);
        console.log('✅ Password reset email sent successfully');
      } catch (emailError) {
        console.error('❌ Failed to send password reset email:', emailError);
      }

      return {
        success: true,
        message: 'If the email is registered, a reset code will be sent.',
      };
    } catch (error) {
      console.error('❌ Send password reset code error:', error);
      throw new HttpException('Something went wrong', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async verifyPasswordResetCode(email: string, code: string) {
    try {
      console.log('🔍 Verifying reset code for email:', email);
      const user = await this.userModel.findOne({ email });
      if (!user) {
        throw new HttpException('Invalid email or code', HttpStatus.BAD_REQUEST);
      }

      if (
        !user.passwordResetCode ||
        user.passwordResetCode !== code ||
        !user.passwordResetExpiry ||
        new Date() > user.passwordResetExpiry
      ) {
        console.log('❌ Invalid or expired reset code');
        throw new HttpException('Invalid or expired reset code', HttpStatus.BAD_REQUEST);
      }

      console.log('✅ Reset code verified successfully');
      return {
        success: true,
        message: 'Reset code verified successfully',
        email: user.email,
      };
    } catch (error) {
      console.error('❌ Verify reset code error:', error);
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async resetPasswordWithCode(email: string, code: string, newPassword: string) {
    try {
      console.log('🔍 Resetting password for email:', email);
      const user = await this.userModel.findOne({ email });
      if (
        !user ||
        !user.passwordResetCode ||
        user.passwordResetCode !== code ||
        !user.passwordResetExpiry ||
        new Date() > user.passwordResetExpiry
      ) {
        console.log('❌ Invalid or expired reset code');
        throw new HttpException('Invalid or expired reset code', HttpStatus.BAD_REQUEST);
      }

      console.log('🔐 Hashing new password...');
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      console.log('💾 Updating user password...');
      user.password = hashedPassword;
      user.passwordResetCode = null;
      user.passwordResetExpiry = null;
      await user.save();

      console.log('✅ Password reset successful for user:', user._id);
      return {
        success: true,
        message: 'Password reset successfully',
      };
    } catch (error) {
      console.error('❌ Reset password error:', error);
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new HttpException('User not found [CHANGE_PASSWORD]', HttpStatus.NOT_FOUND);
      }

      const isCurrentValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentValid) {
        throw new HttpException('Incorrect current password', HttpStatus.BAD_REQUEST);
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;
      await user.save();

      return {
        success: true,
        message: 'Password updated successfully',
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async updateProfile(
    userId: string,
    profileData: {
      title: string;
      firstName: string;
      lastName: string;
      country: string;
      address: string;
      city: string;
      state: string;
      postCode: string;
      phoneNumber: string;
      dateOfBirth: string;
    },
  ) {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new HttpException('User not found [UPDATE_PROFILE]', HttpStatus.NOT_FOUND);
      }

      Object.assign(user, {
        ...profileData,
        dateOfBirth: new Date(profileData.dateOfBirth),
      });

      const requiredFields = [
        'title',
        'firstName',
        'lastName',
        'country',
        'address',
        'city',
        'postCode',
        'phoneNumber',
        'dateOfBirth',
      ];

      // State is optional as not all countries require it
      const isProfileComplete = requiredFields.every(
        (field) => user[field] !== undefined && user[field] !== null && user[field] !== '',
      );

      user.isProfileComplete = isProfileComplete;
      await user.save();

      return {
        success: true,
        message: 'Profile updated successfully',
        user: {
          _id: user._id,
          email: user.email,
          ...profileData,
          dateOfBirth: user.dateOfBirth,
          isProfileComplete: user.isProfileComplete,
          identityVerified: user.identityVerified,
        },
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async getMe(userId: string) {
    try {
      const user = await this.userModel
        .findById(userId)
        .select('-password -verificationCode -verificationCodeExpiry -passwordResetCode -passwordResetExpiry');

      if (!user) {
        throw new HttpException('User not found [GET_ME]', HttpStatus.NOT_FOUND);
      }

      return {
        success: true,
        message: 'Profile fetched successfully',
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
          isProfileComplete: user.isProfileComplete,
          identityVerified: user.identityVerified,
          firstName: user.firstName,
          lastName: user.lastName,
          title: user.title,
          country: user.country,
          address: user.address,
          city: user.city,
          state: user.state,
          postCode: user.postCode,
          phoneNumber: user.phoneNumber,
          dateOfBirth: user.dateOfBirth,
          hasValidPaymentMethod: user.hasValidPaymentMethod,
          paymentMethodVerifiedAt: user.paymentMethodVerifiedAt,
          holdReleaseDate: user.holdReleaseDate,
        },
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async logout(userId: string, res: Response) {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new HttpException('User not found [LOGOUT]', HttpStatus.NOT_FOUND);
      }

      const cookieOptions: any = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      };

      if (process.env.NODE_ENV === 'production') {
        cookieOptions.domain = '.fungibullx.com';
      }

      res.clearCookie('access_token', cookieOptions);

      return {
        success: true,
        message: 'Logged out successfully',
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async resendVerificationCode(userId: string) {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new HttpException('User not found [RESEND_CODE]', HttpStatus.NOT_FOUND);
      }

      if (user.emailVerified) {
        throw new HttpException('Email already verified', HttpStatus.BAD_REQUEST);
      }

      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const verificationCodeExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

      user.verificationCode = verificationCode;
      user.verificationCodeExpiry = verificationCodeExpiry;
      await user.save();

      await this.emailService.sendVerificationEmail(user.email, verificationCode, `${userId}`);

      return {
        success: true,
        message: 'Verification code resent successfully',
      };
    } catch (error) {
      throw new HttpException(
        (error as any).message || 'Something went wrong',
        (error as any).status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
