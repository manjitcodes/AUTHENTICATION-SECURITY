
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");

// The test environment must be configured before loading the app.
if (!process.env.DATABASE_URL) {
  throw new Error(
    "Set DATABASE_URL to your dedicated test database before running tests."
  );
}

const { app } = require("../src/server");
const db = require("../src/db");
const mailer = require("../src/mailer");

const suffix = `${Date.now()}-${Math.random()
  .toString(16)
  .slice(2)}`;

const user = {
  email: `user-${suffix}@example.test`,
  password: "TestPassword!12345",
};

const admin = {
  email: `admin-${suffix}@example.test`,
  password: "AdminPassword!12345",
};

let userAccessToken;
let userRefreshToken;
let resetToken;
let resetDeliveryEmail;

before(() => {
  // Capture reset tokens only in test memory, never in logs or API responses.
  mailer.sendPasswordReset = async (email, rawToken) => {
    resetDeliveryEmail = email;
    resetToken = rawToken;
  };
});

after(async () => {
  try {
    // Remove only records belonging to these uniquely generated test accounts.
    const result = await db.query(
      "SELECT id FROM users WHERE email = ANY($1::text[])",
      [[user.email, admin.email]]
    );

    const ids = result.rows.map((row) => row.id);

    if (ids.length > 0) {
      await db.query(
        "DELETE FROM password_reset_tokens WHERE user_id = ANY($1::int[])",
        [ids]
      );

      await db.query(
        "DELETE FROM refresh_tokens WHERE user_id = ANY($1::int[])",
        [ids]
      );

      await db.query(
        "DELETE FROM users WHERE id = ANY($1::int[])",
        [ids]
      );
    }
  } finally {
    await db.end();
  }
});

test("signup creates a user without returning their password hash", async () => {
  const response = await request(app)
    .post("/auth/signup")
    .send(user);

  assert.equal(response.status, 201);
  assert.equal(response.body.user?.email, user.email);
  assert.equal("password_hash" in response.body, false);
  assert.equal("passwordHash" in response.body, false);
});

test("invalid login returns a generic unauthorized response", async () => {
  const response = await request(app)
    .post("/auth/login")
    .send({
      email: user.email,
      password: "DefinitelyWrongPassword!123",
    });

  assert.equal(response.status, 401);
  assert.match(
    JSON.stringify(response.body).toLowerCase(),
    /invalid|incorrect|credentials/
  );
});

test("protected profile rejects requests without an access token", async () => {
  const response = await request(app).get("/user/profile");

  assert.equal(response.status, 401);
});

test("login issues access and refresh tokens", async () => {
  const response = await request(app)
    .post("/auth/login")
    .send(user);

  assert.equal(response.status, 200);
  assert.equal(typeof response.body.accessToken, "string");
  assert.equal(typeof response.body.refreshToken, "string");

  userAccessToken = response.body.accessToken;
  userRefreshToken = response.body.refreshToken;
});

test("authenticated normal user is forbidden from admin routes", async () => {
  const response = await request(app)
    .get("/admin/dashboard")
    .set("Authorization", `Bearer ${userAccessToken}`);

  assert.equal(response.status, 403);
});

test("refresh rotates the token and rejects reuse of the old token", async () => {
  const oldRefreshToken = userRefreshToken;

  const first = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: oldRefreshToken });

  assert.equal(first.status, 200);
  assert.equal(typeof first.body.refreshToken, "string");
  assert.notEqual(first.body.refreshToken, oldRefreshToken);

  userAccessToken = first.body.accessToken;
  userRefreshToken = first.body.refreshToken;

  const replay = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: oldRefreshToken });

  assert.equal(replay.status, 401);
});

test("password reset uses a generic response and delivers a token privately", async () => {
  const known = await request(app)
    .post("/auth/request-reset")
    .send({ email: user.email });

  const unknown = await request(app)
    .post("/auth/request-reset")
    .send({ email: `unknown-${suffix}@example.test` });

  assert.equal(known.status, unknown.status);
  assert.deepEqual(known.body, unknown.body);
  assert.equal(resetDeliveryEmail, user.email);
  assert.equal(typeof resetToken, "string");
  assert.equal(JSON.stringify(known.body).includes(resetToken), false);
});

test("reset token can be used once and old refresh tokens stop working", async (t) => {
  if (!resetToken) {
    t.skip("Reset-token delivery hook did not capture a token");
    return;
  }

  const newPassword = "ChangedPassword!67890";

const completed = await request(app)
  .post("/auth/complete-reset")
  .send({
    resetToken: resetToken,
    newPassword,
  });

assert.equal(completed.status, 200);

  const reused = await request(app)
    .post("/auth/complete-reset")
    .send({
      resetToken: resetToken,
      newPassword: "AnotherPassword!12345",
    });

  assert.equal(reused.status, 400);

  const oldRefresh = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: userRefreshToken });

  assert.equal(oldRefresh.status, 401);

  const newLogin = await request(app)
    .post("/auth/login")
    .send({
      email: user.email,
      password: newPassword,
    });

  assert.equal(newLogin.status, 200);
});
