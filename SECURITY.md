# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting (the "Report a vulnerability" button under the Security tab),
or email the maintainer. You will get an acknowledgement within a few days.

## What this library does and does not do

authcore-ts is a set of building blocks. It does not protect you from mistakes in the
code that uses it. In particular, you are still responsible for:

- keeping `SESSION_SECRET` secret, at least 32 random bytes, and rotating it if it leaks;
- serving everything over HTTPS (session cookies are `Secure` by default);
- sending the password-reset email and making the endpoint respond identically for known and unknown addresses;
- running one shared rate limiter (`PostgresRateLimiter` or your own) when you run more than one instance;
- trusting `X-Forwarded-For` only when a proxy you control sets it.

Sessions are stateless signed tokens. Signing out clears the cookie in the browser but
does not invalidate the token itself; call `revokeSessions` (or reset the password) to
invalidate every session for a user.
