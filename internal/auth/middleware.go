package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/htb-clone-lab-agent/internal/config"
)

const (
	headerTimestamp = "X-Agent-Timestamp"
	headerNonce     = "X-Agent-Nonce"
	headerSignature = "X-Agent-Signature"
)

type MiddlewareState struct {
	nonce *NonceCache
}

func NewMiddlewareState(nonceTTLSeconds int) *MiddlewareState {
	if nonceTTLSeconds <= 0 {
		nonceTTLSeconds = 360
	}
	return &MiddlewareState{nonce: NewNonceCache(time.Duration(nonceTTLSeconds) * time.Second)}
}

func (s *MiddlewareState) Middleware(cfg config.AuthConfig, next http.Handler) http.Handler {
	mode := strings.ToLower(cfg.Mode)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerOK := false
		hmacOK := false

		if cfg.BearerToken != "" {
			bearerOK = validateBearer(r, cfg.BearerToken)
		}
		if cfg.HMACSecret != "" {
			ok, err := s.validateHMAC(r, cfg.HMACSecret, cfg.HMACSkewSeconds)
			if err == nil {
				hmacOK = ok
			}
		}

		allowed := false
		switch mode {
		case "bearer":
			allowed = bearerOK
		case "hmac":
			allowed = hmacOK
		default:
			allowed = bearerOK || hmacOK
		}

		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"Invalid API authentication.","details":null}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateBearer(r *http.Request, token string) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	return hmac.Equal([]byte(provided), []byte(token))
}

func (s *MiddlewareState) validateHMAC(r *http.Request, secret string, skewSecs int) (bool, error) {
	tsRaw := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	sigRaw := r.Header.Get(headerSignature)
	if tsRaw == "" || nonce == "" || sigRaw == "" {
		return false, fmt.Errorf("missing hmac headers")
	}

	tsUnix, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid timestamp")
	}
	t := time.Unix(tsUnix, 0).UTC()
	if skewSecs <= 0 {
		skewSecs = 300
	}
	now := time.Now().UTC()
	if delta := now.Sub(t); delta > time.Duration(skewSecs)*time.Second || delta < -time.Duration(skewSecs)*time.Second {
		return false, fmt.Errorf("timestamp skew too large")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])

	canonical := r.Method + "\n" + r.URL.Path + "\n" + tsRaw + "\n" + nonce + "\n" + bodyHashHex
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	expected := hex.EncodeToString(mac.Sum(nil))

	received := strings.TrimSpace(sigRaw)
	if !hmac.Equal([]byte(expected), []byte(received)) {
		return false, nil
	}
	if !s.nonce.MarkIfNew(nonce, now.Add(time.Duration(skewSecs+60)*time.Second)) {
		return false, fmt.Errorf("nonce replay detected")
	}
	return true, nil
}
