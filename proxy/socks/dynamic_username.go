package socks

import (
	"crypto/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UsernameCache stores cached usernames with their generation time
type UsernameCache struct {
	username    string
	generatedAt time.Time
}

// DynamicUsernameGenerator handles dynamic username generation for SOCKS5 proxy
type DynamicUsernameGenerator struct {
	pattern   *regexp.Regexp
	kpPattern *regexp.Regexp
	cache     map[string]*UsernameCache
	mutex     sync.RWMutex
}

// NewDynamicUsernameGenerator creates a new dynamic username generator
func NewDynamicUsernameGenerator() *DynamicUsernameGenerator {
	// Pattern to match {sid-N} where N is the number of characters
	pattern := regexp.MustCompile(`\{sid-(\d+)\}`)
	// Pattern to match {kp-N} where N is the keep duration in seconds
	kpPattern := regexp.MustCompile(`\{kp-(\d+)\}`)
	gen := &DynamicUsernameGenerator{
		pattern:   pattern,
		kpPattern: kpPattern,
		cache:     make(map[string]*UsernameCache),
	}

	// Start background cleanup timer
	go gen.startCleanupTimer()

	return gen
}

// GenerateUsername generates a dynamic username based on the template
// Template format: "X_us_{sid-8}" -> "X_us_A1b2C3d4"
// With keep-alive: "X_us_{sid-8}{kp-30}" -> cached username for 30 seconds
func (g *DynamicUsernameGenerator) GenerateUsername(template string) string {
	// Check if template contains keep-alive pattern {kp-N}
	keepDuration := g.extractKeepDuration(template)

	if keepDuration > 0 {
		// Remove {kp-N} from template to get the base template
		baseTemplate := g.kpPattern.ReplaceAllString(template, "")

		// Check if we have a cached username for this base template
		g.mutex.RLock()
		cached, exists := g.cache[baseTemplate]
		g.mutex.RUnlock()

		if exists {
			// Check if the cached username is still valid
			if time.Since(cached.generatedAt).Seconds() < float64(keepDuration) {
				return cached.username
			}
			// Cache expired, remove it
			g.mutex.Lock()
			delete(g.cache, baseTemplate)
			g.mutex.Unlock()
		}

		// Generate new username and cache it
		newUsername := g.generateUsernameInternal(baseTemplate)
		g.mutex.Lock()
		g.cache[baseTemplate] = &UsernameCache{
			username:    newUsername,
			generatedAt: time.Now(),
		}
		g.mutex.Unlock()

		return newUsername
	}

	// No keep-alive pattern, generate username directly
	return g.generateUsernameInternal(template)
}

// generateUsernameInternal generates username without caching logic
func (g *DynamicUsernameGenerator) generateUsernameInternal(template string) string {
	return g.pattern.ReplaceAllStringFunc(template, func(match string) string {
		// Extract the number from {sid-N}
		matches := g.pattern.FindStringSubmatch(match)
		if len(matches) != 2 {
			return match // Return original if parsing fails
		}

		length, err := strconv.Atoi(matches[1])
		if err != nil || length <= 0 {
			return match // Return original if invalid length
		}

		return generateRandomString(length)
	})
}

// startCleanupTimer starts a background timer to periodically clean up expired cache entries
func (g *DynamicUsernameGenerator) startCleanupTimer() {
	ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		g.CleanupExpiredCache()
	}
}

// extractKeepDuration extracts the keep duration from {kp-N} pattern
func (g *DynamicUsernameGenerator) extractKeepDuration(template string) int {
	matches := g.kpPattern.FindStringSubmatch(template)
	if len(matches) != 2 {
		return 0
	}

	duration, err := strconv.Atoi(matches[1])
	if err != nil || duration <= 0 {
		return 0
	}

	return duration
}

// CleanupExpiredCache removes expired cached usernames
func (g *DynamicUsernameGenerator) CleanupExpiredCache() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	now := time.Now()
	for baseTemplate, cached := range g.cache {
		// Calculate how long this cache entry has been around
		age := now.Sub(cached.generatedAt)

		// Clean up entries that are older than 10 minutes
		// This is a reasonable default since most {kp-N} values should be much shorter
		if age.Minutes() > 10 {
			delete(g.cache, baseTemplate)
		}
	}
}

// GetCacheSize returns the current cache size (for monitoring/debugging)
func (g *DynamicUsernameGenerator) GetCacheSize() int {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return len(g.cache)
}

// HasDynamicPattern checks if the username contains dynamic pattern
func (g *DynamicUsernameGenerator) HasDynamicPattern(username string) bool {
	return g.pattern.MatchString(username) || g.kpPattern.MatchString(username)
}

// generateRandomString generates a random alphanumeric string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	// Use crypto/rand for secure random generation
	if _, err := rand.Read(b); err != nil {
		// Fallback to a simple implementation if crypto/rand fails
		return strings.Repeat("X", length)
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}
