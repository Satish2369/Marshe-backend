const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    minlength: 3,
    maxlength: 45,
  },
  uid: {
    type: String,
    required: true,
    unique: true
  },

  email: {
    type: String,
    sparse: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (val) => !val || validator.isEmail(val),
      message: "Invalid email",
    },
  },

  phone: {
    type: String,
    unique: true,
    sparse: true,
  },

  password: {
    type: String,
    minlength: 6,
  },

 

  isPhoneVerified: { type: Boolean, default: false },
  isEmailVerified: { type: Boolean, default: false },
}, { timestamps: true });

// 🔐 Hash password before save
userSchema.pre("save", async function (next) {
  if (this.isModified("password") && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// 🔑 Generate JWT
userSchema.methods.getJWT = function () {
  return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

// 🔐 Validate password
userSchema.methods.validatePassword = async function (passwordByUser) {
  return await bcrypt.compare(passwordByUser, this.password);
};

const UserModel = mongoose.model("User", userSchema);
module.exports = UserModel;
