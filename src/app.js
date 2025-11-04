import express from "express"
import cookieParser from "cookie-parser"
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20"
import config from "./config/config.js";
import authRouter from "./routers/auth.routes.js"
import helmet from "helmet"
import morgan from "morgan";
import cors from "cors"


const app = express()


app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"))


app.use(passport.initialize());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["*"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "blob:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["*", "data:"],
      connectSrc: ["*"],
    },
  })
);

app.use(cors({
  origin: "http://localhost:5173",  // your React app URL
  credentials: true,                // if using cookies or auth headers
}));
// Configure Passport to use Google OAuth 2.0 strategy
passport.use(new GoogleStrategy({
    clientID: config.GOOGLE_CLIENT_ID,
    clientSecret: config.GOOGLE_CLIENT_SECRET,
    callbackURL: '/api/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
    // Here, you would typically find or create a user in your database
    // For this example, we'll just return the profile
    return done(null, profile);
}));

app.use("/api/auth",authRouter)

export default app