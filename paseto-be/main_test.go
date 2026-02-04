package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

const (
	testLocalKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testSeedHex     = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)

type loginResp struct {
	LocalToken string `json:"local_token"`
}

type protectedResp struct {
	LocalToken  string                 `json:"local_token"`
	PublicToken string                 `json:"public_token"`
	Claims      map[string]interface{} `json:"claims"`
}

func newTestApp(t *testing.T) *fiber.App {
	t.Setenv("PASETO_V4_LOCAL_KEY", testLocalKeyHex)
	t.Setenv("PASETO_V4_PUBLIC_SEED", testSeedHex)

	app, err := newApp()
	if err != nil {
		t.Fatalf("newApp error: %v", err)
	}

	return app
}

func TestLoginReturnsLocalToken(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body loginResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(body.LocalToken, "v4.local.") {
		t.Fatalf("expected v4.local token, got %q", body.LocalToken)
	}
}

func TestProtectedRequiresAuth(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestProtectedRejectsInvalidToken(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestProtectedWithLocalTokenReturnsBothTokens(t *testing.T) {
	app := newTestApp(t)

	loginReq := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginHTTPResp, err := app.Test(loginReq)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer loginHTTPResp.Body.Close()

	var loginBody loginResp
	if err := json.NewDecoder(loginHTTPResp.Body).Decode(&loginBody); err != nil {
		t.Fatalf("decode login: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+loginBody.LocalToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body protectedResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(body.LocalToken, "v4.local.") {
		t.Fatalf("expected v4.local token, got %q", body.LocalToken)
	}
	if !strings.HasPrefix(body.PublicToken, "v4.public.") {
		t.Fatalf("expected v4.public token, got %q", body.PublicToken)
	}
	if body.Claims == nil || body.Claims["user-id"] == nil {
		t.Fatalf("expected claims with user-id")
	}
}
