package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/csai/htb-clone-lab-agent/internal/config"
)

func TestHMACValidSignature(t *testing.T) {
	secret := "hmac-secret"
	body := `{"x":1}`
	timestamp := time.Now().UTC().Unix()
	nonce := "nonce-valid"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	state := NewMiddlewareState(360)
	mw := state.Middleware(config.AuthConfig{Mode: "hmac", HMACSecret: secret, HMACSkewSeconds: 300}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/instances", strings.NewReader(body))
	req.Header.Set("X-Agent-Timestamp", int64ToString(timestamp))
	req.Header.Set("X-Agent-Nonce", nonce)
	req.Header.Set("X-Agent-Signature", sign(secret, http.MethodPost, "/v1/instances", int64ToString(timestamp), nonce, []byte(body)))

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHMACBadSignature(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	state := NewMiddlewareState(360)
	mw := state.Middleware(config.AuthConfig{Mode: "hmac", HMACSecret: "secret", HMACSkewSeconds: 300}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/instances", strings.NewReader(`{"x":1}`))
	req.Header.Set("X-Agent-Timestamp", int64ToString(time.Now().UTC().Unix()))
	req.Header.Set("X-Agent-Nonce", "nonce-bad")
	req.Header.Set("X-Agent-Signature", "deadbeef")

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHMACOldTimestamp(t *testing.T) {
	secret := "hmac-secret"
	body := []byte(`{"x":1}`)
	timestamp := int64ToString(time.Now().UTC().Add(-10 * time.Minute).Unix())
	nonce := "nonce-old"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	state := NewMiddlewareState(360)
	mw := state.Middleware(config.AuthConfig{Mode: "hmac", HMACSecret: secret, HMACSkewSeconds: 300}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/instances", strings.NewReader(string(body)))
	req.Header.Set("X-Agent-Timestamp", timestamp)
	req.Header.Set("X-Agent-Nonce", nonce)
	req.Header.Set("X-Agent-Signature", sign(secret, http.MethodPost, "/v1/instances", timestamp, nonce, body))

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHMACNonceReplayRejected(t *testing.T) {
	secret := "hmac-secret"
	body := []byte(`{"x":1}`)
	timestamp := int64ToString(time.Now().UTC().Unix())
	nonce := "nonce-replay"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	state := NewMiddlewareState(360)
	mw := state.Middleware(config.AuthConfig{Mode: "hmac", HMACSecret: secret, HMACSkewSeconds: 300}, next)

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/instances", strings.NewReader(string(body)))
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Nonce", nonce)
		req.Header.Set("X-Agent-Signature", sign(secret, http.MethodPost, "/v1/instances", timestamp, nonce, body))
		return req
	}

	first := httptest.NewRecorder()
	mw.ServeHTTP(first, makeReq())
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	mw.ServeHTTP(second, makeReq())
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("expected second request 401, got %d", second.Code)
	}
}

func sign(secret, method, path, timestamp, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func int64ToString(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
