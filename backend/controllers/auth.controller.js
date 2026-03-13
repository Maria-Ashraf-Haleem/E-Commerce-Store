import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { redis } from "../lib/redis.js";

const generateTokens = (userId) => {
    const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
};

const storedRefreshToken = async (userId, refreshToken) => {
    await redis.set(`refreshToken:${userId}`, refreshToken, {
    ex: 7 * 24 * 60 * 60
});
}

const setCookies=(res, accessToken, refreshToken) => {
    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 15 * 60 * 1000 // 15 minutes
    });
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
};



export const signup = async (req, res) => {
        const { name, email, password } = req.body;
        try{
            const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }
        const user = await User.create({
            name,
            email,
            password
        });
        const {accessToken, refreshToken} = generateTokens(user._id);
        await storedRefreshToken(user._id, refreshToken);

        setCookies(res, accessToken, refreshToken);


        
        res.status(201).json({ user:{ 
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role }, message: "User created successfully" });
        } catch (error) {
            console.log("Error in signup controller:", error.message);
            res.status(500).json({ message: error.message });
        }
    };

export const login = async (req, res) => {
    try{
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (user && await user.comparePassword(password)) {
            const {accessToken, refreshToken} = generateTokens(user._id);
            await storedRefreshToken(user._id, refreshToken);
            setCookies(res, accessToken, refreshToken);
            res.json({ user:{ 
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role }, message: "Login successful" });
        }
    }
    catch(error){
        console.log("Error in login controller:", error.message);
        res.status(500).json({ message: error.message });
    }
};

export const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            if (decoded && decoded.userId) {
                await redis.del(`refreshToken:${decoded.userId}`);
            }
        }
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.json({ message: "Logged out successfully" });
    }
    catch(error){
        console.log("Error in logout controller:", error.message);
        res.status(500).json({ message: error.message });
    }
};

export const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if(!refreshToken){
            return res.status(401).json({ message: "No refresh token provided" });
        }
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const storedToken = await redis.get(`refreshToken:${decoded.userId}`);
        if (storedToken !== refreshToken) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }
        const accessToken = jwt.sign({ userId: decoded.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000 // 15 minutes
        });
        res.json({ message: "Tokens refreshed successfully" });
    }
    catch(error){
        console.log("Error in refresh token controller:", error.message);
        res.status(500).json({ message: error.message });
    }
};

// export const getProfile = async (req, res) => {
//     try {
//         const user = await User.findById(req.userId).select("-password");
//         if (!user) {
//             return res.status(404).json({ message: "User not found" });
//         }
//         res.json({ user });
//     }
