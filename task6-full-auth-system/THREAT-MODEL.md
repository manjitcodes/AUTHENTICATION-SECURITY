# Phase 7 Assignment A7 — Threat Model

## 1. System Overview

The application provides signup, login, JWT-based access authentication, refresh-token rotation, role-based authorization, and password reset. It uses Express, PostgreSQL, bcrypt, and JSON Web Tokens.

The system is intended for a local training environment and is not automatically production-ready.

## 2. Assets to Protect

- User passwords and password hashes
- Access and refresh tokens
- Password-reset tokens
- User account information
- Administrator-only endpoints and data
- Database credentials and JWT signing secrets

## 3. Threats and Defenses

### Password theft

**Threat:** An attacker obtains a database dump and attempts to recover users' passwords.

**Defense:** Store bcrypt password hashes rather than plaintext passwords. Use an appropriate work factor and never return hashes from API endpoints.

**Verification:** Inspect stored records and confirm the signup response does not contain the password or hash.

### SQL injection

**Threat:** An attacker submits crafted input to change the meaning of a database query and bypass authentication or access data.

**Defense:** Use parameterized SQL queries and validate inputs.

**Verification:** Test crafted login input and confirm it cannot authenticate without valid credentials.

### Account enumeration

**Threat:** An attacker determines which email addresses have registered by comparing login or reset responses.

**Defense:** Use a generic login error for invalid credentials and an identical public response for password-reset requests regardless of whether the email exists.

**Verification:** Compare status codes and response bodies for the corresponding cases.

### Stolen or replayed refresh tokens

**Threat:** An attacker uses a stolen refresh token to obtain new access tokens or repeatedly reuses a previously rotated token.

**Defense:** Store refresh-token hashes, apply expiration, rotate tokens on use, and revoke the previous token.

**Verification:** Refresh successfully once and then attempt to reuse the old token.

### Expired or invalid access tokens

**Threat:** An attacker attempts to use a forged, malformed, or expired access token.

**Defense:** Verify the JWT signature, expiration, issuer, and audience on protected requests.

**Verification:** Test missing, malformed, invalid, and expired tokens.

### Privilege escalation

**Threat:** An ordinary user attempts to access administrator functionality.

**Defense:** Enforce role checks on the server and load the current role from the database rather than trusting a client-supplied role.

**Verification:** An ordinary user must receive HTTP 403 from admin-only routes; an authorized admin should succeed.

### Password-reset token theft or replay

**Threat:** An attacker obtains a reset token, uses it after expiration, or reuses it after a successful password change.

**Defense:** Generate unpredictable tokens, store only token hashes, enforce expiration and single use, and revoke existing refresh tokens after a password reset.

**Verification:** Test successful reset, expired token, reused token, and old-password rejection.

### Cross-site scripting

**Threat:** Untrusted user-controlled content is interpreted as executable HTML or JavaScript.

**Defense:** Escape untrusted output and avoid unsafe HTML rendering. Validate input where appropriate.

**Verification:** Submit a harmless XSS test string and confirm it is rendered as text rather than executed.

### Cross-site request forgery

**Threat:** A victim's browser is tricked into making an authenticated request to the application.

**Defense:** The current design uses Bearer tokens supplied in the Authorization header. If the design changes to cookie-based authentication, implement appropriate CSRF defenses and secure cookie attributes.

**Verification:** Inspect how credentials are transported and test any cookie-authenticated state-changing routes.

### Secret leakage

**Threat:** Credentials or tokens are exposed through logs, error messages, source control, or API responses.

**Defense:** Keep secrets in environment variables, exclude `.env` from version control, and avoid logging credentials or tokens.

**Verification:** Review source code, application logs, API responses, and Git tracking status.

## 4. Assumptions and Limitations

- The application is a training project bound to localhost.
- Test accounts contain dummy data.
- Email delivery and production deployment require separate configuration and review.
- Rate limiting, monitoring, HTTPS deployment, and operational secret rotation must be assessed before production use.

## 5. Residual Risk

No checklist or individual test proves that a system is completely secure. The implementation must be reviewed and retested after code or configuration changes.
