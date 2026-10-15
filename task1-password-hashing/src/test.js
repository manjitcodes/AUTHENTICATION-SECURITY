const { signup, login } = require("./auth");
const pool = require("./db");

async function main() {
  const email = `demo-${Date.now()}@example.com`;
  const demoPassword = "DemoPass!2026";

  try {
    const user = await signup(email, demoPassword);
    console.log("Signup successful:", user.email);

    const correctLogin = await login(email, demoPassword);
    console.log(
      "Correct password accepted:",
      correctLogin !== null
    );

    const wrongLogin = await login(email, "WrongPassword123!");
    console.log(
      "Wrong password rejected:",
      wrongLogin === null
    );

    // Inspect the stored hash without printing the password.
    const result = await pool.query(
      "SELECT email, password_hash FROM users WHERE email = $1",
      [email]
    );

    const storedHash = result.rows[0].password_hash;

    console.log("Stored value is a bcrypt hash:", storedHash.startsWith("$2"));
    console.log("Hash length:", storedHash.length);
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error("Test failed:", error.message);
  process.exitCode = 1;
});