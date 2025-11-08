import express from "express"
import * as authenticate from "../controllers/auth.controller.js"
import * as validation from "../middlewares/validation.middleware.js"
import passport from "passport"
import * as authMiddleware from "../middlewares/auth.middleware.js"


// Add this new route

const router = express.Router()


router.post("/register",validation.registerValidationRules ,authenticate.register)
// router.post("/login", login)



// Route to initiate Google OAuth flow
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Callback route that Google will redirect to after authentication
router.get('/google/callback',
  passport.authenticate('google', { session: false }),
  authenticate.googleAuthCallback
);

router.post('/forgot-password', authenticate.forgotPassword)

router.post('/reset-password', validation.resetPasswordValidationRules,authenticate.verifyForgotPassword)

router.post('/login',validation.loginValidationRules,authenticate.login)

router.post('/logout',authenticate.logoutUser)

router.get("/me", authMiddleware.authMiddleware,authenticate.getMe);

export default router
