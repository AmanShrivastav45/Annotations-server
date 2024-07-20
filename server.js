require("dotenv").config();
const User = require("./models/user.model");
const Note = require("./models/note.model");
const Verification = require("./models/otp.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");

const app = express();
connectDB();

const { authenticateToken } = require("./utilities");

app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);

const router = express.Router();

// Function to send OTP
async function sendOTP({ _id, email }, res) {
  try {
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: '"CodeRoom Playground" <coderoom.playground@gmail.com>',
      to: email,
      subject: "OTP Verification Code",
      text: `Your OTP (One Time Password) for verification is: ${otpCode}. This OTP will expire in 5 minutes.`,
    };

    const saltRounds = 10;
    const hashedOTP = await bcrypt.hash(otpCode, saltRounds);
    const newOTPverification = new Verification({
      userId: _id,
      otp: hashedOTP,
      creation: Date.now(),
      expiration: Date.now() + 1800000, // 30 minutes
    });

    await newOTPverification.save();
    await transporter.sendMail(mailOptions);
    console.log("OTP sent:", otpCode);
    res.json({
      status: "PENDING",
      message: "Verification OTP email sent",
      data: {
        userId: _id,
        email,
      },
    });
  } catch (error) {
    console.error("Error in sendOTP:", error);
    res.status(500).json({
      status: "FAILED",
      message: error.message,
    });
  }
}

// Define routes

// Signup route
router.post("/api/signup", async (req, res) => {
  console.log("in backend");
  const { userName, email, password } = req.body;

  try {
    // Check if user already exists
    const isUser = await User.findOne({ email: email });
    if (isUser) {
      return res.status(400).json({
        error: true,
        message: "User already exists!",
      });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new user instance
    const user = new User({
      userName,
      email,
      password: hashedPassword,
      isVerified: false, // Assuming you have this field for OTP verification
    });

    // Save the user to the database
    await user.save();

    // Send OTP to the user
    await sendOTP(user, res);
    // No need to send another response here
    // res.status(201).json({ userId: user._id, message: "User created successfully" });

    console.log("User created successfully");
  } catch (error) {
    console.error("Error in /api/signup:", error);
    res.status(500).json({
      status: "FAILED",
      message: "An error occurred while creating user account",
    });
  }
});

// Login route
router.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  try {
    const userInfo = await User.findOne({ email: email });

    if (!userInfo) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordMatch = await bcrypt.compare(password, userInfo.password);
    if (isPasswordMatch) {
      const user = { user: userInfo };
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "6h",
      });
      return res.json({
        error: false,
        message: "Logged In successfully",
        email,
        accessToken,
      });
    } else {
      return res
        .status(400)
        .json({ error: true, message: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Error in /api/login:", error);
    res.status(500).json({
      status: "FAILED",
      message: "An error occurred while logging in",
    });
  }
});

// Get user route
router.get("/api/getuser", authenticateToken, async (req, res) => {
  const { user } = req.user;
  try {
    const isUser = await User.findOne({ _id: user._id });

    if (!isUser) {
      return res.sendStatus(401);
    }

    return res.json({
      user: {
        userName: isUser.userName,
        email: isUser.email,
        _id: isUser._id,
        joined: isUser.joined,
      },
      message: "User found",
    });
  } catch (error) {
    console.error("Error in /api/getuser:", error);
    res.status(500).json({
      status: "FAILED",
      message: "An error occurred while retrieving user",
    });
  }
});

// Add note route
router.post("/api/addnote", authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const { user } = req.user;

  if (!title)
    return res.status(400).json({ error: true, message: "Title is required" });
  if (!content)
    return res
      .status(400)
      .json({ error: true, message: "Content is required" });

  try {
    const note = new Note({
      title,
      content,
      userId: user._id,
    });
    await note.save();

    return res.json({
      error: false,
      note,
      message: "Note created successfully",
    });
  } catch (error) {
    console.error("Error in /api/addnote:", error);
    return res.status(500).json({
      error: true,
      message: "Internal server error",
    });
  }
});

// Update note route
router.put("/api/updatenote/:noteId", authenticateToken, async (req, res) => {
  const noteId = req.params.noteId;
  const { title, content, isPinned } = req.body;
  const { user } = req.user;

  if (!title && !content) {
    return res.status(400).json({ error: true, message: "No changes made" });
  }

  try {
    const note = await Note.findOne({ _id: noteId, userId: user._id });

    if (!note)
      return res.status(404).json({ error: true, message: "Note not found" });

    if (title) note.title = title;
    if (content) note.content = content;
    if (isPinned) note.isPinned = isPinned;

    await note.save();

    return res.json({
      error: false,
      note,
      message: "Note updated successfully",
    });
  } catch (error) {
    console.error("Error in /api/updatenote:", error);
    return res.status(500).json({
      error: true,
      messgae: "Internal server error",
    });
  }
});

// Delete note route
router.delete(
  "/api/deletenote/:noteId",
  authenticateToken,
  async (req, res) => {
    const noteId = req.params.noteId;
    const { user } = req.user;

    try {
      const note = await Note.findOne({ _id: noteId, userId: user._id });

      if (!note) {
        return res.status(404).json({ error: true, message: "Note not found" });
      }

      await Note.deleteOne({ _id: noteId, userId: user._id });
      return res.json({
        error: false,
        message: "Note deleted successfully",
      });
    } catch (error) {
      console.error("Error in /api/deletenote:", error);
      return res.status(500).json({
        error: true,
        message: "Internal server error",
      });
    }
  }
);

// Get notes route
router.get("/api/getnotes/", authenticateToken, async (req, res) => {
  const { user } = req.user;

  try {
    const notes = await Note.find({
      userId: user._id,
    }).sort({ isPinned: -1 });

    return res.json({
      error: false,
      notes,
      message: "All notes retrieved successfully",
    });
  } catch (error) {
    console.error("Error in /api/getnotes:", error);
    return res.status(500).json({
      error: true,
      message: "Internal server error",
    });
  }
});

// Update pin status route
router.put("/api/updatepin/:noteId", authenticateToken, async (req, res) => {
  const noteId = req.params.noteId;
  const { isPinned } = req.body;
  const { user } = req.user;
  try {
    const note = await Note.findOne({ _id: noteId, userId: user._id });
    console.log(note);
    if (!note)
      return res.status(404).json({ error: true, message: "Note not found" });

    note.isPinned = isPinned;

    await note.save();

    return res.json({
      error: false,
      note,
      message: "Note pinned status updated successfully",
    });
  } catch (error) {
    console.error("Error in /api/updatepin:", error);
    return res.status(500).json({
      error: true,
      message: "Internal server error",
    });
  }
});

// Verify OTP route
router.post("/api/verifyotp", async (req, res) => {
  try {
    let { userId, otp } = req.body;
    if (!userId || !otp) {
      throw new Error("Empty otp details are not allowed");
    } else {
      const record = await Verification.find({ userId });
      if (record.length <= 0) {
        throw new Error(
          "Account record doesn't exist or has been verified already"
        );
      } else {
        const { expiration } = record[0];
        const hashedOTP = record[0].otp;

        if (expiration < Date.now()) {
          await Verification.deleteMany({ userId });
          throw new Error("Code has expired. Please request again");
        } else {
          const valid = await bcrypt.compare(otp, hashedOTP);
          if (!valid) {
            throw new Error("Invalid OTP. Check your mail");
          } else {
            await User.updateOne({ _id: userId }, { isVerified: true });
            await Verification.deleteMany({ userId });
            res.json({
              status: "VERIFIED",
              message: "User email verified successfully!",
            });
          }
        }
      }
    }
  } catch (error) {
    res.json({
      status: "FAILED",
      message: error.message,
    });
  }
});

// Search
router.get("/api/search", authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    console.log(query)
    const userId = req.headers.userid; // Get userId from headers
    console.log(userId)

    if (!query) {
      return res.status(400).json({ message: "Query parameter is required" });
    }

    if (!userId) {
      return res.status(400).json({ message: "Query parameter is required" });
    }

    const notes = await Note.find({
      user: userId, // Use the userId from headers
      $or: [
        { title: { $regex: query, $options: "i" } },
        { content: { $regex: query, $options: "i" } },
      ],
    });
    console.log(notes)
    res.json({ notes });
  } catch (error) {
    console.error("Error searching notes:", error);
    res.status(500).json({ message: "An unexpected error occurred" });
  }
});
// Register router with the app
app.use(router);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
