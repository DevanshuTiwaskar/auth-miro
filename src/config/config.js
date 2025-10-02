import dotenv from "dotenv";

dotenv.config();

const _config = {
  PORT: process.env.PORT,       
  MONGO_URL: process.env.MONGO_URL,   
};

export default Object.freeze(_config);
