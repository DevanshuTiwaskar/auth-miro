import express from "express"
import * as authenticate from "../controllers/auth.controller.js"
import * as validation from "../middlewares/validation.middleware.js"
import passport from "passport"


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

router.post('/forget-password', authenticate.forgetPassword)

router.post('/reset-password', validation.resetPasswordValidationRules,authenticate.verifyForgotPassword)

export default router
