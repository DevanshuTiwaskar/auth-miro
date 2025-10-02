import mongoose from "mongoose";


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true,"username is required"],
        unique: [true,"username already exists"],
    },
    email: {
        type: String,
        required: [true,"email is required"],
        unique: [true,"email already exists"],
    },
    fullName: {
        firstName: {
            type: String,
            required: [true,"first name is required"],
        },
        lastName: {
            type: String,
            required: [true,"last name is required"],
        },
    },

    password: {
        type: String,
    },
    
})

const userModel = mongoose.model("User", userSchema)

export default userModel
