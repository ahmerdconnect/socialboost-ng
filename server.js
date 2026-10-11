require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "socialboost_ng";

if (
  !MONGODB_URI ||
  !process.env.SESSION_SECRET ||
  !process.env.SMTP_HOST ||
  !process.env.SMTP_USER ||
  !process.env.SMTP_PASS ||
  !process.env.MAIL_FROM
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const mongoClient = new MongoClient(MONGODB_URI);

let db;
let users;
let pendingRegistrations;
let transporter;

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later."
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many attempts. Please try again later."
  }
});

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashOTP(otp) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(otp)
    .digest("hex");
}

function createOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 10 &&
    password.length <= 128
  );
}

async function sendOTP(email, otp) {
  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: "Verify your SOCIALBOOST NG account",
    text:
      `Your SOCIALBOOST NG verification code is ${otp}.\n\n` +
      "This code expires in 5 minutes. Do not share it with anyone.",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;padding:24px">
        <h2 style="color:#5b35d5">SOCIALBOOST NG</h2>
        <p>Use the verification code below to confirm your email address.</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:20px 0">
          ${otp}
        </div>
        <p>This code expires in <strong>5 minutes</strong>.</p>
        <p>If you did not request this code, you can ignore this email.</p>
      </div>
    `
  });
}

// Create a new account and send an email OTP.
app.post(
  "/api/auth/register",
  otpLimiter,
  async (req, res, next) => {
    try {
      const name = String(req.body.name || "").trim();
      const email = normalizeEmail(req.body.email);
      const password = req.body.password;

      if (name.length < 2 || name.length > 80) {
        return res.status(400).json({
          success: false,
          message: "Name must contain between 2 and 80 characters."
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid email address."
        });
      }

      if (!validPassword(password)) {
        return res.status(400).json({
          success: false,
          message: "Password must contain between 10 and 128 characters."
        });
      }

      const existingUser = await users.findOne({ email });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: "Unable to create an account with this email."
        });
      }

      const otp = createOTP();
      const otpHash = hashOTP(otp);
      const passwordHash = await bcrypt.hash(password, 12);
      const now = new Date();

      // Store only a hash of the OTP, never the original code.
      await pendingRegistrations.updateOne(
        { email },
        {
          $set: {
            name,
            email,
            passwordHash,
            otpHash,
            expiresAt: new Date(now.getTime() + 5 * 60 * 1000),
            createdAt: now,
            attempts: 0
          }
        },
        { upsert: true }
      );

      try {
        await sendOTP(email, otp);
      } catch (emailError) {
        // Do not leave an unusable registration behind.
        await pendingRegistrations.deleteOne({ email });

        console.error("Email delivery failed.");

        return res.status(503).json({
          success: false,
          message: "We could not send the verification email. Please try again later."
        });
      }

      return res.status(200).json({
        success: true,
        message: "Verification code sent. Check your email."
      });
    } catch (error) {
      next(error);
    }
  }
);

// Verify OTP and activate the account.
app.post(
  "/api/auth/verify-email",
  authLimiter,
  async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body.email);
      const otp = String(req.body.otp || "").trim();

      if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid email and six-digit verification code."
        });
      }

      const registration = await pendingRegistrations.findOne({ email });

      if (!registration) {
        return res.status(400).json({
          success: false,
          message: "Registration not found or code has expired."
        });
      }

      if (registration.expiresAt <= new Date()) {
        await pendingRegistrations.deleteOne({ email });

        return res.status(400).json({
          success: false,
          message: "Verification code has expired. Please register again."
        });
      }

      if (registration.attempts >= 5) {
        await pendingRegistrations.deleteOne({ email });

        return res.status(429).json({
          success: false,
          message: "Too many incorrect attempts. Please register again."
        });
      }

      const suppliedHash = hashOTP(otp);

      if (
        !crypto.timingSafeEqual(
          Buffer.from(suppliedHash, "hex"),
          Buffer.from(registration.otpHash, "hex")
        )
      ) {
        await pendingRegistrations.updateOne(
          { _id: registration._id },
          { $inc: { attempts: 1 } }
        );

        return res.status(400).json({
          success: false,
          message: "Incorrect verification code."
        });
      }

      // A unique database index also prevents duplicate accounts.
      try {
        await users.insertOne({
          name: registration.name,
          email: registration.email,
          passwordHash: registration.passwordHash,
          emailVerified: true,
          createdAt: new Date()
        });
      } catch (error) {
        if (error.code === 11000) {
          await pendingRegistrations.deleteOne({ email });

          return res.status(409).json({
            success: false,
            message: "An account with this email already exists."
          });
        }

        throw error;
      }

      await pendingRegistrations.deleteOne({ _id: registration._id });

      return res.status(201).json({
        success: true,
        message: "Email verified. Your account has been created. You can now log in."
      });
    } catch (error) {
      next(error);
    }
  }
);

// Log in only with a verified account.
app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body.email);
      const password = req.body.password;

      if (
        !validEmail(email) ||
        typeof password !== "string" ||
        password.length > 128
      ) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid email and password."
        });
      }

      const user = await users.findOne({ email });

      if (
        !user ||
        !user.emailVerified ||
        !(await bcrypt.compare(password, user.passwordHash))
      ) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password."
        });
      }

      req.session.userId = user._id.toString();

      return res.json({
        success: true,
        message: "Login successful."
      });
    } catch (error) {
      next(error);
    }
  }
);

// Return basic information for the logged-in customer.
app.get("/api/auth/me", async (req, res, next) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        success: false,
        message: "Please log in."
      });
    }

    const { ObjectId } = require("mongodb");

    if (!ObjectId.isValid(req.session.userId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid session."
      });
    }

    const user = await users.findOne(
      { _id: new ObjectId(req.session.userId) },
      { projection: { name: 1, email: 1, emailVerified: 1, createdAt: 1 } }
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Account not found."
      });
    }

    res.json({
      success: true,
      user
    });
  } catch (error) {
    next(error);
  }
});

// Log out.
app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie("socialboost.sid");
    res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

// Basic health check for hosting providers.
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "SOCIALBOOST NG",
    status: "running"
  });
});

// Return a generic error instead of exposing internal details.
app.use((error, req, res, next) => {
  console.error("Request failed:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    message: "Something went wrong. Please try again later."
  });
});

async function startServer() {
  await mongoClient.connect();

  db = mongoClient.db(DB_NAME);
  users = db.collection("users");
  pendingRegistrations = db.collection("pending_registrations");

  await users.createIndex({ email: 1 }, { unique: true });

  // Automatically remove expired pending registrations.
  await pendingRegistrations.createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 0 }
  );

  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  // Check that the email service configuration is valid.
  await transporter.verify();

  app.use(
    session({
      name: "socialboost.sid",
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        client: mongoClient,
        dbName: DB_NAME,
        collectionName: "sessions"
      }),
      cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
      }
    })
  );

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SOCIALBOOST NG server listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
