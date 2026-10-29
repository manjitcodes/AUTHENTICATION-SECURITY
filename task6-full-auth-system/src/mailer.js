async function sendPasswordReset(email, rawToken) {
  // Replace this with your real email provider for deployment.
  // Never log or return raw reset tokens to API clients.
  throw new Error("Password-reset email delivery is not configured");
}

module.exports = { sendPasswordReset };