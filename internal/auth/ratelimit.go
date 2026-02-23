package auth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/csai/htb-clone-lab-agent/internal/config"
	"github.com/csai/htb-clone-lab-agent/internal/metrics"
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type RateLimiter struct {
	mu           sync.Mutex
	cfg          config.RateLimitConfig
	global       tokenBucket
	perIP        map[string]tokenBucket
	metricRecord func()
}

func NewRateLimiter(cfg config.RateLimitConfig, reg *metrics.Registry) *RateLimiter {
	return &RateLimiter{
		cfg:    cfg,
		global: tokenBucket{tokens: float64(cfg.GlobalBurst), last: time.Now().UTC()},
		perIP:  map[string]tokenBucket{},
		metricRecord: func() {
			if reg != nil {
				reg.IncRateLimited()
			}
		},
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if !rl.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(r) {
			rl.metricRecord()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"throttled","message":"Rate limit exceeded.","details":null}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(r *http.Request) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().UTC()
	if !consume(&rl.global, rl.cfg.GlobalRPS, float64(rl.cfg.GlobalBurst), now) {
		return false
	}
	ip := parseIP(r.RemoteAddr)
	b := rl.perIP[ip]
	if b.last.IsZero() {
		b.last = now
		b.tokens = float64(rl.cfg.PerIPBurst)
	}
	if !consume(&b, rl.cfg.PerIPRPS, float64(rl.cfg.PerIPBurst), now) {
		rl.perIP[ip] = b
		return false
	}
	rl.perIP[ip] = b
	return true
}

func consume(b *tokenBucket, ratePerSec, burst float64, now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * ratePerSec
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func parseIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	if host == "" {
		return remoteAddr
	}
	return host
}
