require("dotenv").config();

const express = require("express");
const session = require("express-session");
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

    // INTENTIONALLY INSECURE: local training exercise only.
    cookie: {
      httpOnly: false,
      secure: false,
      sameSite: false,
    },
  })
);

// Prominent warning on the home page.
app.get("/", (req, res) => {
  res.type("html").send(`
    <h1>VULNERABLE LOGIN FORM</h1>

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

    <p><a href="/me">View my profile</a></p>
  `);
});

// INTENTIONALLY INSECURE: passwords are stored in plaintext.
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send("Email and password are required.");
    }

    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, password]
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

// INTENTIONALLY INSECURE: SQL injection through string concatenation.
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const query =
      `SELECT id, email, password FROM users ` +
      `WHERE email = '${email}' AND password = '${password}'`;

    const result = await db.query(query);

    if (result.rows.length === 0) {
      return res.status(401).send("Invalid email or password.");
    }

    req.session.user = {
      id: result.rows[0].id,
      email: result.rows[0].email,
    };

    res.send(
      `Login successful. <a href="/me">View profile</a>`
    );
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Login failed. Check your training input.");
  }
});

// INTENTIONALLY INSECURE: bio is returned as unescaped HTML.
app.post("/profile/bio", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).send("Please log in first.");
    }

    const { bio } = req.body;

    await db.query(
      "UPDATE users SET bio = $1 WHERE id = $2",
      [bio || "", req.session.user.id]
    );

    res.send('Bio saved. <a href="/me">View your profile</a>');
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

    // INTENTIONALLY INSECURE: user.bio is interpolated directly into HTML.
    res.type("html").send(`
      <h1>${user.email}'s Profile</h1>
      <p>${user.bio}</p>

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

    res.clearCookie("training.sid");
    res.send('Logged out. <a href="/">Home</a>');
  });
});

const PORT = Number(process.env.PORT) || 3003;

app.listen(PORT, "127.0.0.1", () => {
  console.log(`VULNERABLE TRAINING APP: http://127.0.0.1:${PORT}`);
  console.log("LOCAL TRAINING ONLY — DO NOT DEPLOY.");
});