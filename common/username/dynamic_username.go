package username

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

// DynamicUsernameGenerator handles dynamic username generation for proxies
type DynamicUsernameGenerator struct {
	pattern      *regexp.Regexp // {sid-N} pattern for alphanumeric
	didPattern   *regexp.Regexp // {did-N} pattern for digits only
	kpPattern    *regexp.Regexp // {kp-N} pattern for keep-alive
	ipSidPattern *regexp.Regexp // {ip-sid-N} pattern for IP-based alphanumeric
	ipDidPattern *regexp.Regexp // {ip-did-N} pattern for IP-based digits
	cache        map[string]*UsernameCache
	ipCache      map[string]map[string]string // IP -> template -> generated username
	mutex        sync.RWMutex
}

// NewDynamicUsernameGenerator creates a new dynamic username generator
func NewDynamicUsernameGenerator() *DynamicUsernameGenerator {
	// Pattern to match {sid-N} where N is the number of characters
	pattern := regexp.MustCompile(`\{sid-(\d+)\}`)
	// Pattern to match {did-N} where N is the number of digits
	didPattern := regexp.MustCompile(`\{did-(\d+)\}`)
	// Pattern to match {kp-N} where N is the keep duration in seconds
	kpPattern := regexp.MustCompile(`\{kp-(\d+)\}`)
	// Pattern to match {ip-sid-N} where N is the number of characters based on IP
	ipSidPattern := regexp.MustCompile(`\{ip-sid-(\d+)\}`)
	// Pattern to match {ip-did-N} where N is the number of digits based on IP
	ipDidPattern := regexp.MustCompile(`\{ip-did-(\d+)\}`)

	gen := &DynamicUsernameGenerator{
		pattern:      pattern,
		didPattern:   didPattern,
		kpPattern:    kpPattern,
		ipSidPattern: ipSidPattern,
		ipDidPattern: ipDidPattern,
		cache:        make(map[string]*UsernameCache),
		ipCache:      make(map[string]map[string]string),
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

// GenerateUsernameWithIP generates a dynamic username based on the template and client IP
func (g *DynamicUsernameGenerator) GenerateUsernameWithIP(template string, clientIP string) string {
	// If no IP-based patterns, use regular generation
	if !g.hasIPBasedPattern(template) {
		return g.GenerateUsername(template)
	}

	// For IP-based patterns, check cache first
	g.mutex.RLock()
	if ipTemplateCache, exists := g.ipCache[clientIP]; exists {
		if cachedUsername, found := ipTemplateCache[template]; found {
			g.mutex.RUnlock()
			return cachedUsername
		}
	}
	g.mutex.RUnlock()

	// Generate new username based on IP
	newUsername := g.generateIPBasedUsername(template, clientIP)

	// Cache the result
	g.mutex.Lock()
	if g.ipCache[clientIP] == nil {
		g.ipCache[clientIP] = make(map[string]string)
	}
	g.ipCache[clientIP][template] = newUsername
	g.mutex.Unlock()

	return newUsername
}

// hasIPBasedPattern checks if template contains IP-based patterns
func (g *DynamicUsernameGenerator) hasIPBasedPattern(template string) bool {
	return g.ipSidPattern.MatchString(template) || g.ipDidPattern.MatchString(template)
}

// generateIPBasedUsername generates username based on client IP
func (g *DynamicUsernameGenerator) generateIPBasedUsername(template string, clientIP string) string {
	// Create a deterministic seed from client IP
	hash := sha256.Sum256([]byte(clientIP))
	hashStr := hex.EncodeToString(hash[:])

	result := template

	// Handle {ip-sid-N} patterns (IP-based alphanumeric)
	result = g.ipSidPattern.ReplaceAllStringFunc(result, func(match string) string {
		matches := g.ipSidPattern.FindStringSubmatch(match)
		if len(matches) != 2 {
			return match
		}

		length, err := strconv.Atoi(matches[1])
		if err != nil || length <= 0 {
			return match
		}

		return generateDeterministicString(hashStr, length, true)
	})

	// Handle {ip-did-N} patterns (IP-based digits)
	result = g.ipDidPattern.ReplaceAllStringFunc(result, func(match string) string {
		matches := g.ipDidPattern.FindStringSubmatch(match)
		if len(matches) != 2 {
			return match
		}

		length, err := strconv.Atoi(matches[1])
		if err != nil || length <= 0 {
			return match
		}

		return generateDeterministicString(hashStr, length, false)
	})

	// Handle regular patterns if any remain
	result = g.generateUsernameInternal(result)

	return result
}

// generateUsernameInternal generates username without caching logic
func (g *DynamicUsernameGenerator) generateUsernameInternal(template string) string {
	// First handle {sid-N} patterns (alphanumeric)
	result := g.pattern.ReplaceAllStringFunc(template, func(match string) string {
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

	// Then handle {did-N} patterns (digits only)
	result = g.didPattern.ReplaceAllStringFunc(result, func(match string) string {
		// Extract the number from {did-N}
		matches := g.didPattern.FindStringSubmatch(match)
		if len(matches) != 2 {
			return match // Return original if parsing fails
		}

		length, err := strconv.Atoi(matches[1])
		if err != nil || length <= 0 {
			return match // Return original if invalid length
		}

		return generateRandomDigits(length)
	})

	return result
}

// generateDeterministicString generates a deterministic string from hash
func generateDeterministicString(hashStr string, length int, alphanumeric bool) string {
	var charset string
	if alphanumeric {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	} else {
		charset = "0123456789"
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Use different parts of the hash for each character
		hashIndex := (i * 2) % (len(hashStr) - 1)
		if hashIndex+1 < len(hashStr) {
			// Convert two hex characters to a byte value
			hexByte := hashStr[hashIndex : hashIndex+2]
			byteVal := 0
			for _, c := range hexByte {
				byteVal = byteVal*16 + hexCharToInt(c)
			}
			result[i] = charset[byteVal%len(charset)]
		} else {
			result[i] = charset[0]
		}
	}

	return string(result)
}

// hexCharToInt converts a hex character to integer
func hexCharToInt(c rune) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	if c >= 'A' && c <= 'F' {
		return int(c - 'A' + 10)
	}
	return 0
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

	// Clean up IP cache if it gets too large (prevent memory leak)
	if len(g.ipCache) > 10000 {
		// Remove oldest entries (simple cleanup - in production you might want LRU)
		count := 0
		for ip := range g.ipCache {
			if count > 5000 {
				break
			}
			delete(g.ipCache, ip)
			count++
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
	return g.pattern.MatchString(username) || g.didPattern.MatchString(username) ||
		g.kpPattern.MatchString(username) || g.ipSidPattern.MatchString(username) ||
		g.ipDidPattern.MatchString(username)
}

// generateRandomDigits generates a random numeric string of specified length
func generateRandomDigits(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)

	// Use crypto/rand for secure random generation
	if _, err := rand.Read(b); err != nil {
		// Fallback to a simple implementation if crypto/rand fails
		return strings.Repeat("0", length)
	}

	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}

	return string(b)
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

// Global shared instance
var globalGenerator *DynamicUsernameGenerator
var once sync.Once

// GetGlobalDynamicUsernameGenerator returns the global singleton instance
func GetGlobalDynamicUsernameGenerator() *DynamicUsernameGenerator {
	once.Do(func() {
		globalGenerator = NewDynamicUsernameGenerator()
	})
	return globalGenerator
}
