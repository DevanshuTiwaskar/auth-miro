    import { userModel } from "../models/user.model.js";

    export const register = async (req, res) => {
        try {
            const { username, email,fullName:{firstName,lastName}, password } = req.body;

            if(!username || !email || !firstName || !lastName || !password){
                return res.status(400).json({ message: "All fields are required" });
            }

            





            const user = await userModel.create({ username, email, fullName:{firstName,lastName}, password });
            res.status(201).json({ user });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }