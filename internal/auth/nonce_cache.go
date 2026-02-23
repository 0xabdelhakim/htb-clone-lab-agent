package auth

import (
	"sync"
	"time"
)

type NonceCache struct {
	mu         sync.Mutex
	nonces     map[string]time.Time
	defaultTTL time.Duration
}

func NewNonceCache(defaultTTL time.Duration) *NonceCache {
	if defaultTTL <= 0 {
		defaultTTL = 360 * time.Second
	}
	return &NonceCache{nonces: map[string]time.Time{}, defaultTTL: defaultTTL}
}

func (c *NonceCache) MarkIfNew(nonce string, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now().UTC())

	if nonce == "" {
		return false
	}
	if _, exists := c.nonces[nonce]; exists {
		return false
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(c.defaultTTL)
	}
	c.nonces[nonce] = expiresAt
	return true
}

func (c *NonceCache) cleanupLocked(now time.Time) {
	for n, exp := range c.nonces {
		if !exp.After(now) {
			delete(c.nonces, n)
		}
	}
}
