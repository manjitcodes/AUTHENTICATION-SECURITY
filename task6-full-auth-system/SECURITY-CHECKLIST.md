# Phase 7 Assignment A7 — Security Checklist

Project: Full Authentication System  
Stack: Node.js, Express, PostgreSQL, bcrypt, JWT

**Verification rule:** Mark an item VERIFIED only after running the corresponding test against the final code. Record the actual result and date.

## 1. Signup and Login

- [ ] Passwords are hashed with bcrypt before database insertion.
- [ ] Plaintext passwords and password hashes are absent from API responses.
- [ ] Duplicate signup is handled without exposing internal database errors.
- [ ] Login uses parameterized SQL queries.
- [ ] Unknown email and incorrect password produce the same generic failure response.
- [ ] Login does not log passwords, access tokens, or refresh tokens.

## 2. Access and Refresh Tokens

- [ ] Access tokens expire after 15 minutes.
- [ ] JWT signature, issuer, audience, and expiration are verified.
- [ ] Protected endpoints reject missing, malformed, invalid, and expired access tokens.
- [ ] Refresh tokens are stored as hashes in the database.
- [ ] Refresh tokens expire after seven days.
- [ ] Refresh rotates the token and invalidates the previous token.
- [ ] Reusing a rotated or revoked refresh token fails.
- [ ] Logout revokes the supplied refresh token.
- [ ] Password reset revokes existing refresh tokens.
- [ ] Tokens are not written to logs or included in error responses.

## 3. Role-Based Access Control

- [ ] At least two roles exist: user and admin.
- [ ] Protected endpoints require valid authentication.
- [ ] An authenticated user without the required role receives HTTP 403.
- [ ] An admin can access the intended admin-only endpoints.
- [ ] Authorization uses the current role stored in the database.

## 4. Password Reset

- [ ] Reset requests return the same public response for existing and nonexistent emails.
- [ ] Reset tokens are generated securely and stored as hashes.
- [ ] Reset tokens expire after the configured lifetime.
- [ ] An expired token is rejected.
- [ ] A used token cannot be reused.
- [ ] Successful reset changes the password hash.
- [ ] The old password fails and the new password succeeds.
- [ ] Reset tokens are not logged or exposed unintentionally.

## 5. Injection, XSS, Cookies, and CSRF

- [ ] SQL queries use parameterized values or safe ORM operations.
- [ ] User-controlled values are validated.
- [ ] User-generated HTML content is escaped or safely rendered.
- [ ] No authentication tokens are placed in browser-accessible cookies unintentionally.
- [ ] If cookies are used, appropriate HttpOnly, Secure, and SameSite flags are configured.
- [ ] If cookie-based authentication is used, CSRF protections are implemented.
- [ ] Error responses do not expose stack traces, SQL details, passwords, or tokens.

## 6. Configuration and Repository

- [ ] `.env` is ignored by Git.
- [ ] `.env.example` contains placeholders, not real secrets.
- [ ] JWT secrets are not hardcoded in source code.
- [ ] The application binds to localhost for this training project.
- [ ] Tests use dedicated dummy accounts and test data.
- [ ] The final code has been reviewed after the last security change.

## Verification Record

| Test | Expected result | Actual result |
|---|---|---|
| Signup response | 201, no password/hash | Pending |
| Wrong-password login | Generic 401 | Pending |
| SQL injection login attempt | No authentication bypass | Pending |
| Missing access token | 401 | Pending |
| Ordinary user accessing admin route | 403 | Pending |
| Admin accessing admin route | 200 | Pending |
| Refresh token rotation | New token issued | Pending |
| Reuse old refresh token | Rejected | Pending |
| Expired access token | Rejected | Pending |
| Reset request for unknown email | Same public response | Pending |
| Expired reset token | Rejected | Pending |
| Reused reset token | Rejected | Pending |
| Password reset | Old password fails; new password works | Pending |

