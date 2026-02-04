# PASETO v4 Backend Demo

A secure backend implementation using **Go (Fiber)** and **PASETO v4** for authentication. This project demonstrates stateful authentication patterns including:
- Access Tokens (short-lived, stateless verification)
- Refresh Tokens (long-lived, stateful, rotated on use)
- Token Revocation (via Redis)
- Session Management

## Prerequisites

- **Docker** & **Docker Compose** (Recommended)
- **Go 1.25+** (For local development)
- **Redis** (Required for local development)

## Setup

1. **Clone the repository** (if you haven't already).

2. **Configure Environment Variables**:
   Copy the example file to `.env`:
   ```bash
   cp .env.example .env
   ```

3. **Generate Secure Keys**:
   This application requires two 32-byte hex-encoded keys. You can generate them using `openssl`:

   ```bash
   # Generate PASETO_V4_LOCAL_KEY
   openssl rand -hex 32

   # Generate PASETO_V4_PUBLIC_SEED
   openssl rand -hex 32
   ```

   Paste these values into your `.env` file:
   ```env
   PASETO_V4_LOCAL_KEY=your_generated_local_key_here
   PASETO_V4_PUBLIC_SEED=your_generated_public_seed_here
   ```

## Running the Application

### Option 1: Using Docker (Recommended)

Run the entire stack (App + Redis) with a single command:

```bash
docker compose up --build -d
```

- **API URL**: `http://localhost:3001`
- **Redis**: Exposed on port `6380` (to avoid conflict with local Redis running on 6379).
  - *Internal app connection uses port 6379.*

To stop the services:
```bash
docker compose down
```

### Option 2: Running Locally

1. **Start Redis**:
   Ensure you have a Redis instance running on port `6379`.
   ```bash
   redis-server
   ```

2. **Run the Application**:
   ```bash
   go run .
   ```
   The server will start on port `3001`.

## API Documentation

### Auth Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/login` | Issues Access & Refresh tokens | No |
| `POST` | `/refresh` | Rotates Refresh token, issues new Access token | Yes (Bearer Refresh Token) |
| `POST` | `/logout` | Revokes the Refresh token | Yes (Bearer Refresh Token) |
| `GET`  | `/protected` | Returns user claims | Yes (Bearer Access Token) |

### Health Check

- `GET /ping`: Returns `{"hello": "world"}`

## Testing

You can test the authentication flow using `curl`.

**1. Login (Get Tokens)**
```bash
curl -X POST http://localhost:3001/login
```
*Response will contain `access_token` and `refresh_token`.*

**2. Access Protected Route**
```bash
curl -H "Authorization: Bearer <your_access_token>" http://localhost:3001/protected
```

**3. Refresh Tokens**
```bash
curl -X POST -H "Authorization: Bearer <your_refresh_token>" http://localhost:3001/refresh
```

### Automated Test Script
A helper script is included to verify the entire flow:
```bash
./test_auth.sh
```
*Note: If running against Docker, ensure the script points to `localhost:3001`.*

## Architecture Notes

- **Tokens**: PASETO v4 Local (Symmetric).
- **Storage**: Redis is used to store Refresh Token metadata (whitelist/rotation) and Revocation lists.
- **Rotation**: Refresh tokens are single-use. Using an old refresh token will trigger **Reuse Detection**, revoking the entire session family.
