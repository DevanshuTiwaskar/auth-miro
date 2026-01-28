import userModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import otpModel from "../models/otp.model.js";
import { publishMessage } from '../broker/rabbit.js'
import axios from "axios";
import Redis from "ioredis";

// =====================================================
// REDIS CONFIGURATION
// =====================================================
const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
});

redis.on("connect", () =>
  console.log(`✅ Connected to Redis (${process.env.REDIS_HOST}:${process.env.REDIS_PORT})`)

);
redis.on("error", (err) => console.error("❌ Redis connection error:", err));

// =====================================================
// REGISTER CONTROLLER
// =====================================================
export const register = async (req, res) => {
  try {
    const {
      username,
      email,
      fullName: { firstName, lastName },
      password,
      role = "user", // default role
    } = req.body;

    if (!username || !email || !firstName || !lastName || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await userModel.findOne({
      $or: [{ username }, { email }],
    });

    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await userModel.create({
      username,
      email,
      fullName: { firstName, lastName },
      password: hashedPassword,
      role,
    });

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        fullName: {
          firstName: user.fullName.firstName,
          lastName: user.fullName.lastName,
        },
      },
      config.JWT_SECRET,
      {
        expiresIn: "2d",
      }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 2 * 24 * 60 * 60 * 1000,
    });

        await publishMessage("AUTHENTICATION_NOTIFICATION_USER.REGISTERED", {
        email: user.email,
        fullName: `${user.fullName.firstName} ${user.fullName.lastName}`,
        username: user.username
    })

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.fullName,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// =====================================================
// LOGIN CONTROLLER WITH REDIS RATE LIMIT
// =====================================================
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and password are required" });

    const key = `login_attempts:${email}`;
    const attempts = await redis.get(key);

    if (attempts && parseInt(attempts) >= 5)
      return res.status(429).json({
        message: "Too many failed attempts. Try again after 15 minutes.",
      });

    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
      await incrementLoginAttempts(email);
      return res.status(400).json({ message: "Invalid email or password" });
    }

    if (user.googleId) {
      return res.status(400).json({
        message: "Please login using Google for this account.",
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      await incrementLoginAttempts(email);
      return res.status(400).json({ message: "Invalid email or password" });
    }

    await redis.del(key);

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        fullName: {
          firstName: user.fullName.firstName,
          lastName: user.fullName.lastName,
        },
      },
      config.JWT_SECRET,
      {
        expiresIn: "2d",
      }
    );

    await redis.set(`session:${user._id}`, token, "EX", 2 * 24 * 60 * 60);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 2 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.fullName,
      },
      token,
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// Helper function — increment failed login attempts
async function incrementLoginAttempts(email) {
  const key = `login_attempts:${email}`;
  const attempts = await redis.incr(key);
  if (attempts === 1) await redis.expire(key, 15 * 60); // expire after 15 min
}
// =====================================================
// GOOGLE AUTH CALLBACK
// =====================================================
export const googleAuthCallback = async (req, res) => {
  try {
    const {
      id,
      emails: [email],
      name: { givenName: firstName, familyName: lastName },
    } = req.user;

    const username =
      email.value.split("@")[0] + Math.floor(Math.random() * 1000);

    let user = await userModel.findOne({
      $or: [{ googleId: id }, { email: email.value }],
    });

    if (!user) {
      user = await userModel.create({
        username,
        email: email.value,
        googleId: id,
        fullName: { firstName, lastName },
        role: "user",
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        fullName: {
          firstName: user.fullName.firstName,
          lastName: user.fullName.lastName,
        },
      },
      config.JWT_SECRET,
      {
        expiresIn: "2d",
      }
    );

    // ⭐ --- THIS IS THE FIX --- ⭐
    
    // 1. Set the SECURE cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 2 * 24 * 60 * 60 * 1000,
    });

    // 2. Redirect to your FRONTEND callback route
    res.redirect("http://localhost:5173/google-callback");

  } catch (error) {
    console.error("Google Auth Error:", error.message);
    // If it fails, redirect to the login page with an error
    res.redirect("http://localhost:5173/login?error=google-auth-failed");
  }
};
// =====================================================
// FORGOT PASSWORD
// =====================================================
export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await userModel.findOne({ email });

  if (!user) {
    return res
      .status(200)
      .json({ message: "If the email is registered, a OTP will be sent." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpHash = await bcrypt.hash(otp, 10);

  await otpModel.create({
    otp: otpHash,
    email,
    expireIn: new Date(Date.now() + 10 * 60 * 1000),
  });

  try {
    const token = jwt.sign({ email, otp }, config.JWT_SECRET, {
      expiresIn: "10m",
    });

    await axios.post(
      "http://localhost:3001/api/notification/send-forget-password-otp",
      {},
      { headers: { Authorization: `Bearer ${token}` } }
    );

    return res
      .status(200)
      .json({ message: "If the email is registered, a OTP will be sent." });
  } catch (err) {
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// =====================================================
// RESET PASSWORD
// =====================================================
export const verifyForgotPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  const otpDoc = await otpModel.findOne({ email });
  if (!otpDoc)
    return res.status(400).json({ message: "Invalid or expired OTP" });

  const isOtpValid = await bcrypt.compare(otp, otpDoc.otp);
  if (!isOtpValid)
    return res.status(400).json({ message: "Invalid or expired OTP" });

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await userModel.findOneAndUpdate({ email }, { password: hashedPassword });
  await otpModel.findOneAndDelete({ email });

  res.status(200).json({ message: "Password reset successfully" });
};

// =====================================================
// LOGOUT CONTROLLER
// =====================================================
export const logoutUser = async (req, res) => {
  try {
    const token =
      req.cookies?.token || req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No token provided" });

    const decoded = jwt.decode(token);
    const expiresAt = decoded.exp - Math.floor(Date.now() / 1000);

    await redis.set(`bl_${token}`, token, "EX", expiresAt);
    res.clearCookie("token");

    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout Error:", err);
    res.status(500).json({ message: "Something went wrong during logout" });
  }
};



export const getMe = async (req, res) => {
  try {
    // req.user.id is added by your authMiddleware
    const user = await userModel.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
};

function validate(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}
