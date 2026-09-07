# Authentication and account lifecycle

## Browser flow

`/signup` creates an operator account through `POST /api/v1/auth/register` and
starts an HttpOnly session. `/login` authenticates an existing account. `/api/v1/auth/me`
checks the current identity. Logout revokes the stored session before clearing its cookie.

Passwords must contain 12–256 characters and are stored as individually salted
PBKDF2-SHA256 hashes (600,000 iterations). Only digests of opaque session tokens
are stored. Sessions expire after eight hours and survive ordinary server restarts.

Signup accepts only email/password; client-supplied roles are rejected. Configured
`admin@cybershield.ai` and `operator@cybershield.ai` identities cannot be registered
publicly. Registered users own their individual scans and reports. Administrators
remain explicitly configured by deployment secrets; signup never promotes a user.

## Deployment controls

Set `CYBERSHIELD_ALLOW_SIGNUP=false` on the backend to disable public registration.
Existing accounts can still sign in. Cookie authentication requires the configured
trusted origin and `X-CyberShield-Request: 1` on browser mutations. HTTPS deployments
set `CYBERSHIELD_COOKIE_SECURE=true`; local HTTP launch uses false on loopback only.
Registration and login share persistent account/peer rate limiting.

## Limits and recovery

Email strings identify accounts; email ownership is not yet verified through a
mail provider. Do not treat a supplied email domain as proof of organization membership.
Self-service password reset/email delivery is not implemented. Contact the workspace
administrator for recovery; do not expose or publish the database or password hashes.

Backups include registered accounts and hashes. The restore workflow deliberately
revokes old sessions; users sign in again after restoration.
