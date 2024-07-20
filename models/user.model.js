const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  userName: { type: String },
  email: { type: String, unique: true },
  password: { type: String },
  joined: { type: Date, default: new Date().getTime() },
  isVerified: { type: Boolean, default: false },
});

module.exports = mongoose.model("User", userSchema);
