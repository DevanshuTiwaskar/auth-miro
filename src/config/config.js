import dotenv from "dotenv";

dotenv.config();

const _config = {
  PORT: process.env.PORT,
  MONGO_URL: process.env.MONGO_URL,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  FRONTEND_URL: process.env.FRONTEND_URL || "", // Default to relative paths if not set
  RABBITMQ_URI: process.env.RABBITMQ_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  
};

export default Object.freeze(_config);
