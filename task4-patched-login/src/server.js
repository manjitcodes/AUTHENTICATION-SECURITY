require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./db");

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    name: "training.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 60 * 60 * 1000,
    },
  })
);

// Encode user-provided text before inserting it into HTML.
function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };

    return entities[char];
  });
}

app.get("/", (req, res) => {
  res.type("html").send(`
    <h1>PATCHED LOGIN LAB</h1>

    <h2>Sign up</h2>
    <form method="POST" action="/signup">
      <input name="email" type="email" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password" required>
      <button type="submit">Sign up</button>
    </form>

    <h2>Log in</h2>
    <form method="POST" action="/login">
      <input name="email" type="text" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password" required>
      <button type="submit">Log in</button>
    </form>

    <p><a href="/me">View profile</a></p>
  `);
});

// FIX 1: Hash passwords with bcrypt.
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).send("Email and password are required.");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email.trim(), passwordHash]
    );

    res.status(201).json({
      message: "Signup successful",
      user: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).send("Email already registered.");
    }

    console.error(error.message);
    res.status(500).send("Signup failed.");
  }
});

// FIX 2: Parameterized SQL and bcrypt password verification.
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(401).send("Invalid email or password.");
    }

    const result = await db.query(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [email.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).send("Invalid email or password.");
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).send("Invalid email or password.");
    }

    // Regenerate the session ID after successful authentication.
    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).send("Could not create session.");
      }

      req.session.user = {
        id: user.id,
        email: user.email,
      };

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).send("Could not save session.");
        }

        res.send('Login successful. <a href="/me">View profile</a>');
      });
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Login failed.");
  }
});

// Bio updates use a parameterized query.
app.post("/profile/bio", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).send("Please log in first.");
    }

    const bio = typeof req.body.bio === "string" ? req.body.bio : "";

    await db.query(
      "UPDATE users SET bio = $1 WHERE id = $2",
      [bio, req.session.user.id]
    );

    res.send('Bio saved. <a href="/me">View profile</a>');
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Could not save bio.");
  }
});

app.get("/me", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).send(
        'Please log in first. <a href="/">Home</a>'
      );
    }

    const result = await db.query(
      "SELECT id, email, bio FROM users WHERE id = $1",
      [req.session.user.id]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).send("User not found.");
    }

    // FIX 3: Escape both the email and bio before rendering HTML.
    res.type("html").send(`
      <h1>${escapeHtml(user.email)}'s Profile</h1>
      <p>${escapeHtml(user.bio)}</p>

      <form method="POST" action="/profile/bio">
        <textarea name="bio" placeholder="Write your bio"></textarea>
        <button type="submit">Save bio</button>
      </form>

      <form method="POST" action="/logout">
        <button type="submit">Log out</button>
      </form>

      <p><a href="/">Home</a></p>
    `);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Could not load profile.");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).send("Logout failed.");
    }

    res.clearCookie("training.sid", { path: "/" });
    res.send('Logged out. <a href="/">Home</a>');
  });
});

const PORT = Number(process.env.PORT) || 3004;

app.listen(PORT, "127.0.0.1", () => {
  console.log(`PATCHED LOGIN LAB: http://127.0.0.1:${PORT}`);
});