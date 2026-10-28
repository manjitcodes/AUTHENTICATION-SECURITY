const jwt = require("jsonwebtoken");
const crypto = require("crypto");

function createAccessToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      role: user.role,
      email: user.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "15m",
      issuer: "phase7-full-auth",
      audience: "phase7-api",
    }
  );
}

// Generate a high-entropy, opaque token for refresh/reset operations.
function generateOpaqueToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Store only the SHA-256 hash of a refresh or reset token in the DB.
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

module.exports = {
  createAccessToken,
  generateOpaqueToken,
  hashToken,
};