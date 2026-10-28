require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");
const { requireAuth, requireRole } = require("./middleware");
const {
  createAccessToken,
  generateOpaqueToken,
  hashToken,
} = require("./auth");

const app = express();

app.use(express.json({ limit: "10kb" }));

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const GENERIC_RESET_MESSAGE =
  "If that email is registered, reset instructions will be provided.";

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    Buffer.byteLength(password, "utf8") <= 72
  );
}

function validEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Signup
app.post("/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validEmail(email) || !validPassword(password)) {
      return res.status(400).json({
        message: "Provide a valid email and a password of 12-72 bytes.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email, role, created_at`,
      [normalizeEmail(email), passwordHash]
    );

    return res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Unable to create account." });
    }

    console.error("Signup error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const result = await db.query(
      `SELECT id, email, password_hash, role
       FROM users WHERE email = $1`,
      [normalizeEmail(email)]
    );

    const user = result.rows[0];

    // Use a dummy hash when the account doesn't exist to reduce timing leaks.
    const dummyHash =
      "$2b$12$C6UzMDM.H6dfI/f/IKcEe.5b6qPZgTg6zV9W6mV4vM3e0pX1kzM5e";

    const passwordMatches = await bcrypt.compare(
      password,
      user ? user.password_hash : dummyHash
    );

    if (!user || !passwordMatches) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const refreshToken = generateOpaqueToken();
    const refreshHash = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    await db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, refreshHash, expiresAt]
    );

    const accessToken = createAccessToken(user);

    return res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// Refresh: consume the old token and issue a new one atomically.
app.post("/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (typeof refreshToken !== "string" || !refreshToken) {
    return res.status(401).json({ message: "Invalid refresh token." });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT rt.id AS refresh_id, rt.user_id, u.email, u.role
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1
         AND rt.revoked_at IS NULL
         AND rt.expires_at > NOW()
       FOR UPDATE OF rt`,
      [hashToken(refreshToken)]
    );

    const user = result.rows[0];

    if (!user) {
      await client.query("ROLLBACK");
      return res.status(401).json({ message: "Invalid refresh token." });
    }

    await client.query(
      "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1",
      [user.refresh_id]
    );

    const nextRefreshToken = generateOpaqueToken();

    await client.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [
        user.user_id,
        hashToken(nextRefreshToken),
        new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
      ]
    );

    await client.query("COMMIT");

    const accessToken = createAccessToken({
      id: user.user_id,
      email: user.email,
      role: user.role,
    });

    return res.json({
      accessToken,
      refreshToken: nextRefreshToken,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Refresh error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  } finally {
    client.release();
  }
});

// Logout: revoke the refresh token.
app.post("/auth/logout", async (req, res) => {
  const { refreshToken } = req.body;

  if (typeof refreshToken === "string" && refreshToken) {
    try {
      await db.query(
        `UPDATE refresh_tokens
         SET revoked_at = NOW()
         WHERE token_hash = $1 AND revoked_at IS NULL`,
        [hashToken(refreshToken)]
      );
    } catch (error) {
      console.error("Logout error:", error.message);
      return res.status(500).json({ message: "Internal server error." });
    }
  }

  return res.status(204).end();
});

// Password reset request: always return the same public response.
app.post("/auth/request-reset", async (req, res) => {
  try {
    const email =
      typeof req.body.email === "string"
        ? normalizeEmail(req.body.email)
        : "";

    if (validEmail(email)) {
      const result = await db.query(
        "SELECT id FROM users WHERE email = $1",
        [email]
      );

      if (result.rows.length > 0) {
        const userId = result.rows[0].id;
        const resetToken = generateOpaqueToken();

        // Invalidate any outstanding reset tokens for this account.
        await db.query(
          `UPDATE password_reset_tokens
           SET used_at = NOW()
           WHERE user_id = $1 AND used_at IS NULL`,
          [userId]
        );

        await db.query(
          `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
           VALUES ($1, $2, $3)`,
          [
            userId,
            hashToken(resetToken),
            new Date(Date.now() + RESET_TOKEN_TTL_MS),
          ]
        );

        // Local training only. In a real app, send this via a trusted email service.
        if (process.env.NODE_ENV !== "production") {
          console.log(`[LOCAL RESET TOKEN] ${email}: ${resetToken}`);
        }
      }
    }
  } catch (error) {
    // Don't return a different message for unknown emails or operational errors.
    console.error("Reset request error:", error.message);
  }

  return res.json({ message: GENERIC_RESET_MESSAGE });
});

// Complete reset: lock and consume the token in a single transaction.
app.post("/auth/complete-reset", async (req, res) => {
  const { resetToken, newPassword } = req.body;

  if (
    typeof resetToken !== "string" ||
    !resetToken ||
    !validPassword(newPassword)
  ) {
    return res.status(400).json({ message: "Invalid or expired reset token." });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, user_id
       FROM password_reset_tokens
       WHERE token_hash = $1
         AND used_at IS NULL
         AND expires_at > NOW()
       FOR UPDATE`,
      [hashToken(resetToken)]
    );

    const tokenRecord = result.rows[0];

    if (!tokenRecord) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        message: "Invalid or expired reset token.",
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    await client.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [passwordHash, tokenRecord.user_id]
    );

    await client.query(
      "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1",
      [tokenRecord.id]
    );

    // Revoke all existing refresh tokens after password reset.
    await client.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [tokenRecord.user_id]
    );

    await client.query("COMMIT");

    return res.json({ message: "Password reset successful." });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Complete reset error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  } finally {
    client.release();
  }
});

// Protected routes
app.get("/user/profile", requireAuth, (req, res) => {
  res.json({
    message: "Authenticated user profile",
    user: req.user,
  });
});

app.get("/admin/dashboard", requireAuth, requireRole("admin"), (req, res) => {
  res.json({ message: "Welcome to the admin dashboard." });
});

// A second admin-only action.
app.get("/admin/users", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, email, role, created_at FROM users ORDER BY id"
    );

    res.json({ users: result.rows });
  } catch (error) {
    console.error("Admin users error:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get("/health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ status: "ok" });
  } catch {
    res.status(503).json({ status: "database unavailable" });
  }
});

const port = Number(process.env.PORT) || 3005;

app.listen(port, "127.0.0.1", () => {
  console.log(`Full auth API running at http://127.0.0.1:${port}`);
});