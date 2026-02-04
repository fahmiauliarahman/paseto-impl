# Redis + PASETO v4 Token Flow (Real-World, High Level)

This document describes a production-style token flow using PASETO v4 with Redis
for refresh-token state and rotation. It is framework-agnostic and does not
reference the current code in this repo.

## Goals

- Short-lived access tokens for APIs.
- Long-lived refresh tokens for session continuity.
- Rotation + server-side state to detect token reuse.
- Support both web (cookies) and mobile/SDK (headers).

## Claim Meanings (Quick Reference)
- `iss` (issuer): Who minted the token (e.g., `auth-service`).
  Used to reject tokens from unknown issuers.
- `aud` (audience): Who the token is intended for (e.g., `api.example.com`).
  Prevents token reuse across different services.
- `sub` (subject): The principal the token represents (usually a user ID).
- `iat` (issued at): When the token was created (RFC3339 time).
- `nbf` (not before): Earliest time the token is valid.
- `exp` (expiration): Latest time the token is valid.
- `jti` (JWT ID / token ID): Unique token identifier used for rotation/revocation.
- `typ` (type): `access` vs `refresh`, used to enforce correct usage by endpoint.
- `sid` (session ID): Groups a user's login session for mass revoke/log out everywhere.
- `kid` (key ID, in footer): Identifies which key signed/encrypted the token for key rotation.

## Token Types

- **Access token**: `v4.local`, TTL ~5–15 minutes.
- **Refresh token**: `v4.local`, TTL ~7–30 days.
- `typ` claim is required (`access` vs `refresh`).
- Include `jti` for uniqueness and revocation.

## Redis Data Model (Recommended)

- `refresh:<jti>` → hash of refresh token + metadata
  - Fields: `user_id`, `session_id`, `issued_at`, `expires_at`, `fingerprint`
  - TTL: refresh token TTL
- `session:<session_id>:revoked` → boolean flag
  - TTL: refresh token TTL (or longer)
- Optional: `access_block:<jti>` → used only if you need immediate access-token
  revocation (otherwise access tokens remain stateless)

**Hashing**: store only a hash of the refresh token (e.g., HMAC-SHA256 with a
server secret). Never store raw refresh tokens.

## Frontend → Backend Flow

### 1) Login (Web: cookie + header)

1. Client sends credentials to `POST /login`.
2. Backend authenticates and issues:
   - Access token (`access`)
   - Refresh token (`refresh`)
3. Backend stores refresh token hash in Redis `refresh:<jti>`.
4. Backend response:
   - JSON: access token
   - Set-Cookie: refresh token (HttpOnly, Secure, SameSite=Lax/Strict)
5. Client keeps access token in memory and sends it via
   `Authorization: Bearer <access>` for APIs.

### 2) Login (Mobile/SDK: headers only)

1. Client sends credentials to `POST /login`.
2. Backend issues access + refresh tokens.
3. Backend stores refresh hash in Redis.
4. Backend returns both tokens in JSON.
5. Client stores access/refresh in secure storage.

### 3) Protected API Request

1. Client calls `GET /protected` with `Authorization: Bearer <access>`.
2. Backend verifies access token signature/claims (no Redis lookup).
3. If valid, process request and return response.

### 4) Refresh

#### Web (cookie)

1. Client calls `POST /refresh` (no Authorization header).
2. Browser sends refresh cookie automatically.
3. Backend:
   - Verifies refresh token.
   - Checks `typ=refresh` and `jti` presence.
   - Looks up `refresh:<jti>` in Redis.
   - If missing → treat as reuse/theft → revoke session.
4. If valid, rotate:
   - Delete old `refresh:<jti>`.
   - Issue new access + refresh tokens.
   - Store new refresh hash in Redis.
   - Return access token + set new refresh cookie.

#### Mobile/SDK (header)

1. Client calls `POST /refresh` with `Authorization: Bearer <refresh>`
   (or a dedicated `X-Refresh-Token` header).
2. Same validation + rotation as web flow.
3. Backend returns new access + refresh in JSON.

### 5) Logout / Revoke

1. Client calls `POST /logout`.
2. Backend deletes `refresh:<jti>` from Redis or sets
   `session:<session_id>:revoked`.
3. Web: clear refresh cookie.

## Rotation & Reuse Detection

- **Rotation**: every refresh replaces the refresh token and invalidates the
  previous one.
- **Reuse detection**: if a refresh token is used but `refresh:<jti>` is missing,
  treat it as theft and revoke the session (and optionally all user sessions).

## Claims & Rules

Recommended claims for both access and refresh:
- `iss`, `aud`, `sub`
- `iat`, `nbf`, `exp`
- `jti` (unique per token)
- `typ` (`access` or `refresh`)
- `sid` (session ID, useful for mass revoke)

Parser rules:
- `NotExpired()`
- `ValidAt(now)`
- `IssuedBy(issuer)` and `ForAudience(aud)`
- `Subject` or `jti` checks as needed

## Claim Examples + Recommended Validation

Example claim set for an **access token**:

```json
{
  "iss": "auth-service",
  "aud": "api.example.com",
  "sub": "user_123",
  "iat": "2026-02-04T12:00:00Z",
  "nbf": "2026-02-04T12:00:00Z",
  "exp": "2026-02-04T12:15:00Z",
  "jti": "0f53c0d6-9a1b-4c25-9c2d-2c6b7c3f9a21",
  "typ": "access",
  "sid": "sess_7f9d5a3b"
}
```

Recommended validations:

- `iss` → must equal your issuer string (e.g., `auth-service`).
- `aud` → must match the API/service hostname.
- `typ` → must be `access` for API calls, `refresh` for `/refresh`.
- `exp`/`nbf`/`iat` → reject expired or not‑yet‑valid tokens.
- `jti` → optional for access; required for refresh rotation.
- `sid` → optional but useful for session‑level revoke.

## Custom Claims (Example: Email)

Custom data lives **in the token payload**, alongside standard claims at the
same JSON level. It is not stored in the footer and not in implicit assertions.
For example, you can include `email` **in access tokens only**:

```json
{
  "email": "user@example.com"
}
```

Guidelines:

- Keep custom claims minimal and non‑sensitive.
- Avoid putting PII you don’t need on every request.
- If you must include email, prefer access tokens only (short TTL).
- Never put refresh tokens in local storage if you can use HttpOnly cookies.

Where to put it (summary):

- **Payload** (claims JSON): ✅ custom claims go here.
- **Footer**: ❌ keep for metadata like `kid` (key ID).
- **Implicit assertion**: ❌ advanced usage; not for user data.

## Glossary / Abbreviations

- **PII**: Personally Identifiable Information (data that can identify a person).
- **TTL**: Time To Live (how long a token is valid before expiring).
- **API**: Application Programming Interface (the backend endpoints your app calls).
- **SDK**: Software Development Kit (client libraries for mobile/desktop apps).
- **JWT**: JSON Web Token (a different token format; `jti` naming comes from JWT).
- **HMAC**: Hash-based Message Authentication Code (used for secure hashing/verification).
- **SHA-256**: Secure Hash Algorithm 256-bit (a common cryptographic hash).
- **RFC3339**: Standard timestamp format (e.g., `2026-02-04T12:00:00Z`).
- **KMS**: Key Management Service (managed system for storing/rotating secrets).
- **iss**: Issuer (who minted the token).
- **aud**: Audience (who the token is intended for).
- **sub**: Subject (the user or entity the token represents).
- **iat**: Issued At (when the token was created).
- **nbf**: Not Before (earliest time the token is valid).
- **exp**: Expiration (latest time the token is valid).
- **jti**: JWT ID (unique token identifier).
- **typ**: Type (e.g., `access` or `refresh`).
- **sid**: Session ID (groups a login session for mass revoke).
- **kid**: Key ID (which key signed/encrypted the token).

## Key Management

- Use **different keys** for access vs refresh tokens.
- Rotate keys via `kid` (in footer) + key registry.
- Keep keys out of source control and protect with KMS/Secrets Manager.

## Local vs Public (Decision Table)

| Use case | Choose | Why |
| --- | --- | --- |
| Only your backend must read claims | `v4.local` | Encrypts payload; only holders of the symmetric key can read it. |
| Multiple services must verify tokens without sharing secrets | `v4.public` | Anyone with the public key can verify signatures. |
| You need confidentiality of user data in token | `v4.local` | Payload is encrypted, not just signed. |
| Tokens will be validated by third parties | `v4.public` | Public key distribution is safe. |
| Minimal infrastructure, single service | `v4.local` | Simple symmetric key management. |

## Error Handling (Typical)

- `401 Unauthorized`: missing/invalid access or refresh token
- `403 Forbidden`: revoked session or reuse detected
- `429 Too Many Requests`: refresh abuse
- `500 Internal Server Error`: key/Redis misconfiguration

## Summary

- Access tokens are fast and stateless.
- Refresh tokens are stateful and tracked in Redis.
- Rotation + reuse detection protects against token theft.
- Cookies for web, headers for mobile/SDK.
- **Use `v4.local`** when you need confidentiality (only the server can read claims).
- **Use `v4.public`** when other services must verify tokens without sharing secrets.

## Read more about PASETO

- Official site: [paseto.io](https://paseto.io)
- Specification: [paseto-standard/paseto-spec](https://github.com/paseto-standard/paseto-spec)
- Reference implementation (PHP): [paragonie/paseto](https://github.com/paragonie/paseto)
- Overview article: [What is PASETO?](https://developer.okta.com/blog/2019/05/07/what-is-paseto)
