package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

func main() {
	app, err := newApp()
	if err != nil {
		panic(err)
	}

	if err := app.Listen(":3001"); err != nil {
		panic(err)
	}
}

type keys struct {
	local paseto.V4SymmetricKey
}

type config struct {
	issuer             string
	audience           string
	accessTokenTTL     time.Duration
	refreshTokenTTL    time.Duration
	tokenHashSecret    string
	corsAllowedOrigins map[string]struct{}
}

type appContext struct {
	keys   keys
	config config
	redis  *redis.Client
}

func newApp() (*fiber.App, error) {
	app := fiber.New()

	// Load keys and config
	k, err := loadKeys()
	if err != nil {
		return nil, err
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	// Initialize Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Test Redis connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	appCtx := &appContext{
		keys:   k,
		config: cfg,
		redis:  rdb,
	}

	app.Use(corsMiddleware(appCtx))

	// Routes
	app.Get("/ping", func(c fiber.Ctx) error {
		return c.JSON(map[string]string{
			"hello": "world",
		})
	})

	app.Post("/login", loginHandler(appCtx))
	app.Post("/refresh", refreshHandler(appCtx))
	app.Post("/logout", logoutHandler(appCtx))
	app.Get("/protected", authAccessMiddleware(appCtx), protectedHandler())

	return app, nil
}

func loadKeys() (keys, error) {
	localHex := os.Getenv("PASETO_V4_LOCAL_KEY")
	if localHex == "" {
		return keys{}, fmt.Errorf("missing PASETO_V4_LOCAL_KEY")
	}
	localKey, err := paseto.V4SymmetricKeyFromHex(localHex)
	if err != nil {
		return keys{}, err
	}

	return keys{local: localKey}, nil
}

func loadConfig() (config, error) {
	issuer := os.Getenv("TOKEN_ISSUER")
	if issuer == "" {
		issuer = "paseto-be"
	}

	audience := os.Getenv("TOKEN_AUDIENCE")
	if audience == "" {
		audience = "api.example.com"
	}

	accessTTL, err := time.ParseDuration(getEnvOrDefault("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		return config{}, fmt.Errorf("invalid ACCESS_TOKEN_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(getEnvOrDefault("REFRESH_TOKEN_TTL", "168h"))
	if err != nil {
		return config{}, fmt.Errorf("invalid REFRESH_TOKEN_TTL: %w", err)
	}

	// Use a separate secret for token hashing (or derive from PASETO key)
	hashSecret := os.Getenv("TOKEN_HASH_SECRET")
	if hashSecret == "" {
		hashSecret = os.Getenv("PASETO_V4_LOCAL_KEY") // fallback to PASETO key
	}

	corsOrigins := getEnvOrDefault("CORS_ALLOWED_ORIGINS", "http://localhost:5173")

	return config{
		issuer:             issuer,
		audience:           audience,
		accessTokenTTL:     accessTTL,
		refreshTokenTTL:    refreshTTL,
		tokenHashSecret:    hashSecret,
		corsAllowedOrigins: parseAllowedOrigins(corsOrigins),
	}, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseAllowedOrigins(raw string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, origin := range strings.Split(raw, ",") {
		o := strings.TrimSpace(origin)
		if o == "" {
			continue
		}
		allowed[o] = struct{}{}
	}
	return allowed
}

func corsMiddleware(appCtx *appContext) fiber.Handler {
	allowed := appCtx.config.corsAllowedOrigins

	return func(c fiber.Ctx) error {
		origin := c.Get("Origin")
		if origin != "" {
			if _, ok := allowed["*"]; ok || containsOrigin(allowed, origin) {
				c.Set("Access-Control-Allow-Origin", origin)
				c.Set("Vary", "Origin")
				c.Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
				c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				c.Set("Access-Control-Max-Age", "600")
			}
		}

		if c.Method() == fiber.MethodOptions {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	}
}

func containsOrigin(allowed map[string]struct{}, origin string) bool {
	_, ok := allowed[origin]
	return ok
}

// Token generation
func issueAccessToken(userID, sessionID string, appCtx *appContext, now time.Time) (string, string, error) {
	jti := uuid.New().String()
	token := paseto.NewToken()

	// Standard claims
	token.SetIssuer(appCtx.config.issuer)
	token.SetAudience(appCtx.config.audience)
	token.SetSubject(userID)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(now.Add(appCtx.config.accessTokenTTL))
	token.SetJti(jti)

	// Custom claims
	token.SetString("typ", "access")
	token.SetString("sid", sessionID)
	token.SetString("user-id", userID)

	return token.V4Encrypt(appCtx.keys.local, nil), jti, nil
}

func issueRefreshToken(userID, sessionID string, appCtx *appContext, now time.Time) (string, string, error) {
	jti := uuid.New().String()
	token := paseto.NewToken()

	// Standard claims
	token.SetIssuer(appCtx.config.issuer)
	token.SetAudience(appCtx.config.audience)
	token.SetSubject(userID)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(now.Add(appCtx.config.refreshTokenTTL))
	token.SetJti(jti)

	// Custom claims
	token.SetString("typ", "refresh")
	token.SetString("sid", sessionID)
	token.SetString("user-id", userID)

	return token.V4Encrypt(appCtx.keys.local, nil), jti, nil
}

// Token parsing and validation
func parseAccessToken(appCtx *appContext, raw string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now()))
	parser.AddRule(paseto.IssuedBy(appCtx.config.issuer))
	parser.AddRule(paseto.ForAudience(appCtx.config.audience))

	token, err := parser.ParseV4Local(appCtx.keys.local, raw, nil)
	if err != nil {
		return nil, err
	}

	// Validate token type
	typ, err := token.GetString("typ")
	if err != nil || typ != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	return token, nil
}

func parseRefreshToken(appCtx *appContext, raw string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now()))
	parser.AddRule(paseto.IssuedBy(appCtx.config.issuer))
	parser.AddRule(paseto.ForAudience(appCtx.config.audience))

	token, err := parser.ParseV4Local(appCtx.keys.local, raw, nil)
	if err != nil {
		return nil, err
	}

	// Validate token type
	typ, err := token.GetString("typ")
	if err != nil || typ != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	return token, nil
}

// Redis operations
func storeRefreshToken(appCtx *appContext, jti, userID, sessionID string, expiresAt time.Time) error {
	key := fmt.Sprintf("refresh:%s", jti)
	ttl := time.Until(expiresAt)

	err := appCtx.redis.HSet(ctx, key, map[string]interface{}{
		"user_id":    userID,
		"session_id": sessionID,
		"issued_at":  time.Now().Unix(),
		"expires_at": expiresAt.Unix(),
	}).Err()
	if err != nil {
		return err
	}

	return appCtx.redis.Expire(ctx, key, ttl).Err()
}

func deleteRefreshToken(appCtx *appContext, jti string) error {
	key := fmt.Sprintf("refresh:%s", jti)
	return appCtx.redis.Del(ctx, key).Err()
}

func validateRefreshToken(appCtx *appContext, jti string) (bool, error) {
	key := fmt.Sprintf("refresh:%s", jti)
	exists, err := appCtx.redis.Exists(ctx, key).Result()
	return exists > 0, err
}

func revokeSession(appCtx *appContext, sessionID string) error {
	// Mark session as revoked
	key := fmt.Sprintf("session:%s:revoked", sessionID)
	return appCtx.redis.Set(ctx, key, "1", appCtx.config.refreshTokenTTL).Err()
}

func isSessionRevoked(appCtx *appContext, sessionID string) (bool, error) {
	key := fmt.Sprintf("session:%s:revoked", sessionID)
	exists, err := appCtx.redis.Exists(ctx, key).Result()
	return exists > 0, err
}

// Hash token for storage (HMAC-SHA256)
func hashToken(token, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// Handlers
func loginHandler(appCtx *appContext) fiber.Handler {
	return func(c fiber.Ctx) error {
		// In production, you'd validate credentials here
		// For demo purposes, we'll use a static user
		userID := "demo-user"
		sessionID := uuid.New().String()
		now := time.Now()

		// Issue tokens
		accessToken, _, err := issueAccessToken(userID, sessionID, appCtx, now)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to issue access token",
			})
		}

		refreshToken, refreshJTI, err := issueRefreshToken(userID, sessionID, appCtx, now)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to issue refresh token",
			})
		}

		// Store refresh token in Redis
		expiresAt := now.Add(appCtx.config.refreshTokenTTL)
		if err := storeRefreshToken(appCtx, refreshJTI, userID, sessionID, expiresAt); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to store refresh token",
			})
		}

		return c.JSON(fiber.Map{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(appCtx.config.accessTokenTTL.Seconds()),
		})
	}
}

func refreshHandler(appCtx *appContext) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract refresh token from Authorization header
		auth := c.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing or invalid authorization header",
			})
		}

		rawToken := strings.TrimPrefix(auth, "Bearer ")

		// Parse and validate refresh token
		token, err := parseRefreshToken(appCtx, rawToken)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid refresh token",
			})
		}

		// Get jti and session ID
		jti, err := token.GetString("jti")
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing jti claim",
			})
		}

		sessionID, err := token.GetString("sid")
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing session ID",
			})
		}

		userID, err := token.GetString("user-id")
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing user ID",
			})
		}

		// Check if session is revoked
		revoked, err := isSessionRevoked(appCtx, sessionID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to check session status",
			})
		}
		if revoked {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "session revoked",
			})
		}

		// Validate refresh token exists in Redis
		exists, err := validateRefreshToken(appCtx, jti)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to validate refresh token",
			})
		}

		if !exists {
			// Reuse detected! Revoke the entire session
			_ = revokeSession(appCtx, sessionID)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "token reuse detected - session revoked",
			})
		}

		// Delete old refresh token (rotation)
		if err := deleteRefreshToken(appCtx, jti); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to rotate token",
			})
		}

		// Issue new tokens
		now := time.Now()
		newAccessToken, _, err := issueAccessToken(userID, sessionID, appCtx, now)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to issue access token",
			})
		}

		newRefreshToken, newRefreshJTI, err := issueRefreshToken(userID, sessionID, appCtx, now)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to issue refresh token",
			})
		}

		// Store new refresh token
		expiresAt := now.Add(appCtx.config.refreshTokenTTL)
		if err := storeRefreshToken(appCtx, newRefreshJTI, userID, sessionID, expiresAt); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to store refresh token",
			})
		}

		return c.JSON(fiber.Map{
			"access_token":  newAccessToken,
			"refresh_token": newRefreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(appCtx.config.accessTokenTTL.Seconds()),
		})
	}
}

func logoutHandler(appCtx *appContext) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract refresh token from Authorization header
		auth := c.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing or invalid authorization header",
			})
		}

		rawToken := strings.TrimPrefix(auth, "Bearer ")

		// Parse refresh token
		token, err := parseRefreshToken(appCtx, rawToken)
		if err != nil {
			// Even if token is invalid/expired, we can still try to extract jti
			// For now, just return success
			return c.JSON(fiber.Map{
				"message": "logged out successfully",
			})
		}

		// Get jti and session ID
		jti, _ := token.GetString("jti")
		sessionID, _ := token.GetString("sid")

		// Delete refresh token
		if jti != "" {
			_ = deleteRefreshToken(appCtx, jti)
		}

		// Optionally revoke entire session
		if sessionID != "" {
			_ = revokeSession(appCtx, sessionID)
		}

		return c.JSON(fiber.Map{
			"message": "logged out successfully",
		})
	}
}

func protectedHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		token, ok := c.Locals("token").(*paseto.Token)
		if !ok || token == nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		userID, err := token.GetString("user-id")
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(fiber.Map{
			"message": "access granted",
			"user_id": userID,
			"claims":  token.Claims(),
		})
	}
}

// Middleware
func authAccessMiddleware(appCtx *appContext) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := c.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		raw := strings.TrimPrefix(auth, "Bearer ")
		token, err := parseAccessToken(appCtx, raw)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		// Check if session is revoked
		sessionID, err := token.GetString("sid")
		if err == nil {
			revoked, err := isSessionRevoked(appCtx, sessionID)
			if err == nil && revoked {
				return c.SendStatus(fiber.StatusForbidden)
			}
		}

		c.Locals("token", token)
		return c.Next()
	}
}
