
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const pool = require("./db");

const { requireAuth, requireRole } = require("./middleware");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required in .env");
}

app.use(express.json());

app.use(
  session({
    name: "session_id",
    store: new PgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: "strict",
      maxAge: 60 * 60 * 1000,
    },
  })
);

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Authentication API is running" });
});

// Register: public signups always get the user role.
app.post("/auth/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Provide a valid email and a password of 8-72 bytes.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, 'user')
       RETURNING id, email, role`,
      [email.trim().toLowerCase(), passwordHash]
    );

    return res.status(201).json({
      message: "Account created. Please log in.",
      user: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "An account with that email already exists.",
      });
    }

    next(error);
  }
});

// Login: verify the password and establish a server-side session.
app.post("/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash, role
       FROM users
       WHERE email = $1`,
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    // Regenerate the session ID after successful authentication.
    req.session.regenerate((error) => {
      if (error) return next(error);

      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role,
      };

      req.session.save((error) => {
        if (error) return next(error);

        return res.json({
          message: "Login successful.",
          user: req.session.user,
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Return the currently authenticated user's information.
app.get("/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// Logout and invalidate the server-side session.
app.post("/auth/logout", requireAuth, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie("session_id", {
      httpOnly: true,
      secure: isProduction,
      sameSite: "strict",
      path: "/",
    });

    return res.json({ message: "Logged out successfully." });
  });
});

// Protected route: normal users must receive 403.
app.get("/admin/dashboard", requireAuth, requireRole("admin"), (req, res) => {
  res.json({
    message: "Admin access granted.",
    user: req.session.user,
  });
});

// Demonstration route: any authenticated user can access this.
app.get("/user/profile", requireAuth, (req, res) => {
  res.json({
    message: "Authenticated access granted.",
    user: req.session.user,
  });
});

// Central error handler.
app.use((error, req, res, next) => {
  console.error(error);

  if (res.headersSent) return next(error);

  return res.status(500).json({
    error: "Internal server error.",
  });
});

async function startServer() {
  await pool.query("SELECT 1");

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
