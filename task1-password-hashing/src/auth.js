const bcrypt = require("bcrypt");
const pool = require("./db");

const SALT_ROUNDS = 12;

async function signup(email, plainPassword) {
  if (
    typeof email !== "string" ||
    typeof plainPassword !== "string" ||
    !email.trim() ||
    !plainPassword
  ) {
    throw new Error("Email and password are required");
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Hash the password before storing it.
  const passwordHash = await bcrypt.hash(
    plainPassword,
    SALT_ROUNDS
  );

  try {
    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email, created_at`,
      [normalizedEmail, passwordHash]
    );

    // Never return the password or hash to the caller.
    return result.rows[0];
  } catch (error) {
    if (error.code === "23505") {
      throw new Error("Could not create account");
    }

    throw error;
  }
}

async function login(email, plainPassword) {
  if (
    typeof email !== "string" ||
    typeof plainPassword !== "string"
  ) {
    return null;
  }

  const normalizedEmail = email.trim().toLowerCase();

  const result = await pool.query(
    `SELECT id, email, password_hash
     FROM users
     WHERE email = $1`,
    [normalizedEmail]
  );

  const user = result.rows[0];

  if (!user) {
    return null;
  }

  const isValid = await bcrypt.compare(
    plainPassword,
    user.password_hash
  );

  if (!isValid) {
    return null;
  }

  return {
    id: user.id,
    email: user.email,
  };
}

module.exports = { signup, login };
