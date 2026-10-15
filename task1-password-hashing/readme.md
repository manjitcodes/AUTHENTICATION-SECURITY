# Sessions vs JWT

## Sessions

In session-based authentication, a user submits their credentials and the server verifies them. The server creates a session and stores the session data in a database or a session store such as Redis. The client receives a session ID, usually in a secure cookie, and sends it with subsequent requests. The server looks up the session ID to determine whether the user is authenticated.

A major advantage of sessions is revocation. If an administrator needs to terminate a user's access immediately, the server can invalidate that user's session. The trade-off is that the application needs reliable shared session storage when running across multiple servers.

**Example:** I would choose sessions for a traditional web application where users sign in to manage their account and administrators need to revoke access immediately.

## JWT

JWT stands for JSON Web Token. After verifying a user's credentials, the server creates a signed token containing claims such as the user's ID and expiration time. The client sends the token with subsequent requests, and the server verifies its signature and expiration.

JWTs can reduce the need for a central session lookup because a server can validate a token using its signing key. However, revoking an individual JWT before it expires is more difficult unless the application uses a denylist, token versioning, short expiration times, or another revocation mechanism.

A signed JWT is not necessarily encrypted. Its payload can generally be read by anyone who obtains the token, so sensitive information should not be placed in it.

**Example:** I would consider short-lived JWT access tokens for an API serving mobile and web clients, particularly when multiple services need to verify authentication.

## Conclusion

Sessions maintain authentication state on the server, while JWTs carry signed claims in the token. Neither approach is universally better. The right choice depends on revocation requirements, application architecture, and security needs.