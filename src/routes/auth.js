const express = require("express");
const validator = require("validator");
const User = require("../models/user");
const { validateSignUpData } = require("../utils/validation");
const { userAuth } = require("../../middlewares/auth");

const authRouter = express.Router();


authRouter.post('/signup/email', async (req, res) => {
  try {
    // Validate the incoming data
    validateSignUpData(req);

    const { password, name, email } = req.body;

   
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }
    const emailUid = `email_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;

  
    const user = new User({
      name,
      email,
      password,
      uid: emailUid,
    });

    const savedUser = await user.save();
    const token = await savedUser.getJWT();

    
    res.cookie("token", token, {
      expires: new Date(Date.now() + 8 * 3600000), 
      httpOnly: true,
      sameSite: "Lax",
      secure: process.env.NODE_ENV === "production",
    });

    res.status(201).json({
      message: "User saved successfully",
      data: savedUser,
    });

  } catch (err) {
    res.status(400).send("Error: " + err.message);
  }
});


authRouter.post("/login/email", async (req, res) => {
  try {
    const { password, email } = req.body;

    if (!validator.isEmail(email)) {
      throw new Error("Invalid email");
    }

    const user = await User.findOne({ email });
  
    if (!user) throw new Error("Invalid credentials");


    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) throw new Error("Invalid credentials");

    
    const token = await user.getJWT();

    res.cookie("token", token, {
      expires: new Date(Date.now() + 8 * 3600000),
      httpOnly: true,
      sameSite: "Lax",
      secure: process.env.NODE_ENV === "production",
    });

    res.status(200).json({
      message: "Login successful",
      data: {
        name: user.name,
        email: user.email,
      },
    });

  } catch (err) {
    res.status(400).send("ERROR: " + err.message);
  }
});


authRouter.post("/login/otp", async (req, res) => {
  try {
    const { uid, phone } = req.body;

    if (!uid || !phone) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Invalid Firebase UID or phone number",
      });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({
        error: "Not Found",
        message: "User not found",
      });
    }

    const token = await user.getJWT();

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      success: true,
      message: "OTP login successful",
      data: {
        _id: user._id,
        name: user.name,
        email: user.email || null,
        phone: user.phone,
        uid: user.uid,
      },
    });

  } catch (error) {
    console.error("OTP Login Error:", error.message);
    return res.status(500).json({
      error: "Internal Server Error",
      message: error.message,
    });
  }
});


authRouter.post("/signup/otp", async (req, res) => {
  try {
    const { name, phone, uid } = req.body;

    if (!name || !phone || !uid) {
      return res.status(400).json({
        success: false,
        message: "Name, phone, and UID are required",
      });
    }

    const existingUser = await User.findOne({ uid, phone });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists with this phone/uid",
      });
    }

    const user = new User({ name, phone, uid });
    await user.save();

    const token = await user.getJWT();

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      success: true,
      message: "User signed up successfully",
      data: {
        uid,
        name,
        phone,
      },
    });

  } catch (error) {
    console.error("OTP Signup Error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
});


authRouter.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.send("Logout successfully");
});


authRouter.get("/profile", userAuth, async (req, res) => {
  try {
    const user = req.user;
    const { name, email } = user;

    res.status(200).json({
      message: "User profile fetched successfully",
      data: { name, email },
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch profile",
      error: error.message,
    });
  }
});

module.exports = authRouter;
