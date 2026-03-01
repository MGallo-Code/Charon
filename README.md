# Charon

> ***The ferryman who decides who crosses, you're not getting past without him!***

A standalone, session-based authentication service in Go. Can be integrated with any product that needs auth. Contains logic for registration, login, OAuth, email verification, password reset, CSRF protection, rate limiting, and audit logging, all in one place.

> **Note**: Rate limiting works based on content *(For example, logins are limited based on request body's email)*. Services like Kong are expected for any ip-based rate limiting.

Built for production scale!

---

## Features

- **Email/password auth**: register, login, logout, logout-all
- **Google OAuth**: PKCE + OIDC, account linking via email confirmation
- **Session management**: Redis-cached, Postgres-durable, configurable TTLs
- **CSRF protection**: token injected at login, validated on every state-changing request
- **Email verification**: required by default, resend supported
- **Password reset**: token-based, single-use, time-limited
- **Password policy**: configurable min/max length, uppercase, digit, special character requirements
- **Rate limiting**: per-identity, per-endpoint, Redis-backed with configurable windows and lockouts
- **CAPTCHA**: Cloudflare Turnstile support, per-endpoint toggles
- **Audit log**: every auth event written to Postgres for compliance and incident response
- **Health check**: pings Postgres and Redis, returns structured status

---

## Quick Start

```bash
# Copy config and fill in values
cp .env.example .env

# Start Postgres + Redis + Charon
docker compose up -d
```

Charon listens on port `7865` by default.

---

## API

All responses are JSON. Errors use `{"error":"..."}`, success uses `{"message":"..."}` or a data object.

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Postgres + Redis health check |
| `POST` | `/register/email` | Register with email and password |
| `POST` | `/login/email` | Login, receive session cookie + CSRF token |
| `POST` | `/verify/email` | Consume email verification token |
| `POST` | `/send/verify/email` | Resend verification email |
| `POST` | `/send/reset/password` | Request a password reset email |
| `POST` | `/password/confirm` | Consume reset token, set new password |
| `GET` | `/oauth/{provider}` | Start OAuth flow (redirects to provider) |
| `GET` | `/oauth/{provider}/callback` | OAuth callback, issues session on success |
| `POST` | `/oauth/link/confirm` | Confirm OAuth account link via emailed token |

### Authenticated

Requires `__Host-session` cookie. All state-changing requests also require `X-CSRF-Token` header.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/logout` | Invalidate current session |
| `POST` | `/logout-all` | Invalidate all sessions for the user |
| `POST` | `/password/change` | Change password (invalidates all sessions) |

---

## Architecture

```
Kong (rate limiting, CORS, TLS termination)
  -> Charon (Go, stateless)
    -> Redis  (session cache, rate limiting, mail queue)
    -> Postgres (users, sessions, tokens, audit log)
```

Charon is stateless. Any instance can serve any request. In production, one could ideally scale horizontally behind a load balancer.

Redis is optional. Without it, sessions fall back to Postgres and rate limiting is disabled. Enable Redis before production.

### Sessions

Session-based, not JWT, because sessions can be invalidated instantly (logout, password change, suspected compromise). JWTs cannot, hence my decision here.

Each session is:
- A 256-bit random token, SHA-256 hashed before storage
- Cached in Redis for sub-millisecond validation
- Written to Postgres as a backup source of truth
- Delivered as an `HttpOnly Secure SameSite=Lax __Host-` cookie

---

## Configuration

Copy `.env.example` to `.env`. All values are environment variables.

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Postgres connection string |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | _(disabled)_ | Redis connection string. Enables session cache and rate limiting. *(Recommended for efficiency)* |
| `PORT` | `7865` | HTTP listen port |
| `MAX_BODY_BYTES` | `8192` | Request body size limit |
| `SESSION_TTL` | `24h` | Session lifetime |
| `SESSION_REMEMBER_ME_TTL` | `720h` | Session lifetime when remember-me is set |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | Block login until email is verified |

### SMTP (email features)

Leave `SMTP_HOST` unset to disable outbound email. Password reset and email verification require SMTP.

| Variable | Description |
|----------|-------------|
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | SMTP port (typically `587`) |
| `SMTP_USERNAME` | SMTP username |
| `SMTP_PASSWORD` | SMTP password |
| `SMTP_FROM` | From address |
| `SMTP_RESET_URL` | Base URL for password reset links |
| `SMTP_VERIFY_URL` | Base URL for email verification links |
| `SMTP_OAUTH_LINK_URL` | Base URL for OAuth account link confirmation |
| `MAIL_QUEUE_ENC_KEY` | 32-byte AES-256 key for encrypting queued emails in Redis |

### Google OAuth

Leave `GOOGLE_CLIENT_ID` unset to disable Google sign-in.

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | Must match a registered redirect URI in Google Cloud Console |

### Password Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSWORD_MIN_LENGTH` | `8` | Minimum password length (runes/characters) |
| `PASSWORD_MAX_LENGTH` | `128` | Maximum password length (runes/characters) |
| `PASSWORD_REQUIRE_UPPERCASE` | `false` | Require at least one uppercase letter |
| `PASSWORD_REQUIRE_DIGIT` | `false` | Require at least one digit |
| `PASSWORD_REQUIRE_SPECIAL` | `false` | Require at least one special character |

### Rate Limiting

Requires Redis. Each endpoint has three modifiers: max attempts, window, and lockout duration.

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LOGIN_EMAIL_MAX` | `10` | Max login attempts before lockout |
| `RATE_LOGIN_EMAIL_WINDOW` | `10m` | Attempt counting window |
| `RATE_LOGIN_EMAIL_LOCKOUT` | `15m` | Lockout duration after threshold |
| `RATE_REGISTER_EMAIL_MAX` | `5` | Max registrations per window |
| `RATE_REGISTER_EMAIL_WINDOW` | `1h` | |
| `RATE_REGISTER_EMAIL_LOCKOUT` | `1h` | |
| `RATE_RESET_MAX` | `3` | Max password reset requests |
| `RATE_RESET_WINDOW` | `1h` | |
| `RATE_RESET_LOCKOUT` | `1h` | |
| `RATE_RESEND_MAX` | `3` | Max resend verification requests |
| `RATE_RESEND_WINDOW` | `1h` | |
| `RATE_RESEND_LOCKOUT` | `1h` | |

### CAPTCHA

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_CAPTCHA_ENABLED` | `false` | Enable CAPTCHA verification |
| `SECURITY_CAPTCHA_PROVIDER` | | `turnstile` (Cloudflare) |
| `SECURITY_CAPTCHA_SECRET` | | Provider secret key |
| `SECURITY_CAPTCHA_REGISTER` | `false` | Require CAPTCHA on register |
| `SECURITY_CAPTCHA_LOGIN` | `false` | Require CAPTCHA on login |
| `SECURITY_CAPTCHA_PASSWORD_RESET` | `false` | Require CAPTCHA on password reset request |
| `SECURITY_CAPTCHA_PASSWORD_CONFIRM` | `false` | Require CAPTCHA on password reset confirmation |
| `SECURITY_CAPTCHA_RESEND_VERIFICATION` | `false` | Require CAPTCHA on resend verification email |
| `SECURITY_CAPTCHA_VERIFY_EMAIL` | `false` | Require CAPTCHA on email verification |
| `SECURITY_CAPTCHA_CONFIRM_OAUTH_LINK` | `false` | Require CAPTCHA on OAuth link confirmation |

---

## Development

```bash
# Start local Postgres + Redis
docker compose up -d

# Run the server
make run

# Run all tests (starts test DB automatically)
make test

# Build binary
make build
```

Tests run against a separate test database on port `5433` (see `compose.test.yml`). Store integration tests and e2e tests are skipped when the compose stack is not running.

---

## Adding an OAuth Provider

1. Implement `oauth.Provider` in `internal/oauth/`
2. Register it in `main.go` under `oauthProviders`
3. Add a `CHECK` constraint for the new provider name to the `users` and `oauth_pending_links` tables

The generic `OAuthRedirect` and `OAuthCallback` handlers handle the rest.
