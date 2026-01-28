import express from "express";
import * as authenticate from "../controllers/auth.controller.js";
import * as validation from "../middlewares/validation.middleware.js";
import passport from "passport";
import * as authMiddleware from "../middlewares/auth.middleware.js";

const router = express.Router();

/* ======================
   HEALTH CHECK (NEW)
====================== */
router.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "auth",
    timestamp: new Date().toISOString(),
  });
});

/* ======================
   AUTH ROUTES
====================== */
router.post(
  "/register",
  validation.registerValidationRules,
  authenticate.register
);

router.post(
  "/login",
  validation.loginValidationRules,
  authenticate.login
);

router.post("/logout", authenticate.logoutUser);

router.get(
  "/me",
  authMiddleware.authMiddleware,
  authenticate.getMe
);

/* ======================
   GOOGLE OAUTH
====================== */
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  authenticate.googleAuthCallback
);

/* ======================
   PASSWORD RESET
====================== */
router.post("/forgot-password", authenticate.forgotPassword);

router.post(
  "/reset-password",
  validation.resetPasswordValidationRules,
  authenticate.verifyForgotPassword
);

export default router;
