const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// OTP Schema
const otpSchema = new Schema({
  userId: {type: String, required: true},
  otp: { type: String, required: true },
  creation: {type: Date, default: new Date().getTime()},
  expiration: {type: Date, default: new Date().getTime() + 1800000},
});

module.exports = mongoose.model("Verification", otpSchema);

