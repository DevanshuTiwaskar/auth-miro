import  userModel  from "../models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import otpModel from "../models/otp.model.js";

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
     const isUserAlreadyExists = await userModel.findOne({ $or: [{username},{email}] }) 

    const hash = await bcrypt.hash(password, 10);

    const user = await userModel.create({
      username,
      email,
      fullName: { firstName, lastName },
      password: hash,
    });
    

    const token = jwt.sign({
      id: user._id,
    },config.JWT_SECRET, {expiresIn: "2d"})


     res.cookie("token", token)



    res.status(201).json({
        message: "User registered successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName
        }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


export const googleAuthCallback = async function (req,res) {
  
  const { id, emails:[ email], name: {giveName: firstName, familyName: lastName}} = req.body
 
  const username = email.value.split("@")[ 0 ] + Math.floor(Math.random() * 1000)

  const isUserAlreadyExists = await userModel.findOne({
    $or : [{ googleId: id}, {email: email.value}]
  })

  if(isUserAlreadyExists){
    const token = jwt.sign({
      id: isUserAlreadyExists.id,
    },config.JWT_SECRET,{ expiresIn: "2d" })
    res.cookie("token",token)


    return res.status(200).json({
      message: "Google authentication successful",
        id: isUserAlreadyExists.id,
        username: isUserAlreadyExists.username,
        email: isUserAlreadyExists.email,
        fullName: isUserAlreadyExists.fullName
    })
  }


const  user = await userModel.create({
  username,
  email: email.value,
  googleId: id,
  fullName: {
    firstName,
    lastName
  }
})

const token = jwt.sign({
  id: user._id
},config.JWT_SECRET,{ expiresIn: "2d"})

res.cookie("token",token)

res.status(201).json({
  id: user.id,
  username: user.username,
  email: user.email,
  fullName: user.fullName
})



}


export const forgetPassword = async function (req,res) {
   const { email } =  req.body

   const isUserExisted = await userModel.findOne({email});
  
   if(!isUserExisted){
    return res.status(200).json({message: "If the Email is registered, Otp will be send"})
   }


   const otp = Math.floor(100000 + Math.random() * 900000).toString()

   const otpHash = await bcrypt.hash(otp,10)
   
   await otpModel.create({
    otp: otpHash,
    email,
    expireIn: new Date(Date.now() +  10 * 60 * 1000) ///10 minutes from now
   })


   try {
     
    const token = jwt.sign({email,otp},config.JWT_SECRET, {expiresIn: '10m'})

    const response = await axios.post('http//localhost:3001/api/notification/send-forgot-password-otp',{},{
      headers: {Authorization: `bearer ${token}`}
    })

    return res.status(200).json({message: "If the Email is registered,A Otp will be send"})
   } catch (error) {
    return res.status(500).json({message: "something went wrong"})
   }

}




export const verifyForgotPassword = async function (req,res) {
    
  const { email, otp, newPassword} = req.body

  const otpDoc = await otpModel.findOne({email})

  if(!otpDoc){
    return res.status(400).json({message: "Invalid or expired OTP"})
  }


  const isOtpvvalid = await bcrypt.compare(otp, otpDoc.otp);


  if(!isOtpvvalid){
    return res.status(400).json({message: "Invalid or expired OTP"})
  }

  const hashedPassword = await bcrypt.hash(newPassword,10)

  await userModel.findOneAndUpdate({email},{password: hashedPassword})

  await otpModel.findOneAndDelete({email});

  res.status(200).json({message: "password reset successfully"})

}