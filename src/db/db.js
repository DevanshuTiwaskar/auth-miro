import mongoose from "mongoose";
import config from "../config/config.js";

const connectDB = async () => {
  try {
    await mongoose.connect(config.MONGO_URL);
    console.log("✅ Database of auth is connected successfully");
  } catch (error) {
    console.error("❌ Database connection failed:", error.message);
  }
};

export default connectDB;
