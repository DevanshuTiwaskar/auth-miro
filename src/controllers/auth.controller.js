import userModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import otpModel from "../models/otp.model.js";
import axios from "axios";
import Redis from "ioredis"; 

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
    
});

redis.on("connect", () => {
  console.log("✅ Connected to Redis Cloud successfully!");
});

redis.on("error", (err) => {
  console.error("❌ Redis connection error:", err);
});
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
    } = req.body;

    if (!username || !email || !firstName || !lastName || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const isUserAlreadyExists = await userModel.findOne({
      $or: [{ username }, { email }],
    });

    if (isUserAlreadyExists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await userModel.create({
      username,
      email,
      fullName: { firstName, lastName },
      password: hash,
    });

    const token = jwt.sign({ id: user._id }, config.JWT_SECRET, {
      expiresIn: "2d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 2 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
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

    // 1️⃣ Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const key = `login_attempts:${email}`;
    const attempts = await redis.get(key);

    // 2️⃣ Block if too many failed attempts (5 in 15 mins)
    if (attempts && parseInt(attempts) >= 5) {
      return res
        .status(429)
        .json({ message: "Too many failed attempts. Try again after 15 minutes." });
    }

    // 3️⃣ Find user
    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
      await incrementLoginAttempts(email);
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // 4️⃣ Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await incrementLoginAttempts(email);
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // ✅ Successful login → reset attempts
    await redis.del(key);

    // 5️⃣ Generate JWT token
    const token = jwt.sign({ id: user._id }, config.JWT_SECRET, {
      expiresIn: "2d",
    });

    // 6️⃣ Save session in Redis (optional)
    await redis.set(`session:${user._id}`, token, "EX", 2 * 24 * 60 * 60); // expire in 2 days

    // 7️⃣ Send HTTP-only cookie
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
        fullName: user.fullName,
      },
      token,
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// Helper — increment failed attempts in Redis
async function incrementLoginAttempts(email) {
  const key = `login_attempts:${email}`;
  const attempts = await redis.incr(key);
  if (attempts === 1) {
    await redis.expire(key, 15 * 60); // expire after 15 min
  }
}

// =====================================================
// GOOGLE AUTH CALLBACK (unchanged)
// =====================================================
export const googleAuthCallback = async function (req, res) {
  const {
    id,
    emails: [email],
    name: { givenName: firstName, familyName: lastName },
  } = req.user;

  const username =
    email.value.split("@")[0] + Math.floor(Math.random() * 1000);

  const isUserAlreadyExists = await userModel.findOne({
    $or: [{ googleId: id }, { email: email.value }],
  });

  if (isUserAlreadyExists) {
    const token = jwt.sign({ id: isUserAlreadyExists.id }, config.JWT_SECRET, {
      expiresIn: "2d",
    });
    res.cookie("token", token);

    return res.status(200).json({
      message: "Google authentication successful",
      id: isUserAlreadyExists.id,
      username: isUserAlreadyExists.username,
      email: isUserAlreadyExists.email,
      fullName: isUserAlreadyExists.fullName,
    });
  }

  const user = await userModel.create({
    username,
    email: email.value,
    googleId: id,
    fullName: { firstName, lastName },
  });

  const token = jwt.sign({ id: user._id }, config.JWT_SECRET, {
    expiresIn: "2d",
  });

  res.cookie("token", token);
  res.status(201).json({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
  });
};

// =====================================================
// FORGOT PASSWORD
// =====================================================
export const forgotPassword = async function (req, res) {
  const { email } = req.body;
  const isUserExists = await userModel.findOne({ email });

  if (!isUserExists) {
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
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    return res
      .status(200)
      .json({ message: "If the email is registered, a OTP will be sent." });
  } catch (err) {
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// =====================================================
// VERIFY FORGOT PASSWORD
// =====================================================
export const verifyForgotPassword = async function (req, res) {
  const { email, otp, newPassword } = req.body;

  const otpDoc = await otpModel.findOne({ email });
  if (!otpDoc) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  const isOtpValid = await bcrypt.compare(otp, otpDoc.otp);
  if (!isOtpValid) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await userModel.findOneAndUpdate({ email }, { password: hashedPassword });
  await otpModel.findOneAndDelete({ email });

  res.status(200).json({ message: "Password reset successfully" });
};


// ✅ Logout controller
export const logoutUser = async (req, res) => {
  try {
    // Get token from cookie or Authorization header
    const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
    
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Add token to Redis blacklist with expiry same as token
    const decoded = jwt.decode(token);
    const expiresAt = decoded.exp - Math.floor(Date.now() / 1000); // in seconds

    await redis.set(`bl_${token}`, token, "EX", expiresAt);

    // Clear cookie
    res.clearCookie("token");

    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout Error:", err);
    res.status(500).json({ message: "Something went wrong during logout" });
  }
};
