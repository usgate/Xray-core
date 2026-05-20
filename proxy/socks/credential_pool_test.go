package socks

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestCredentialPoolUsesVerifiedCredentialBeforeFallback(t *testing.T) {
	manager := newTestCredentialPoolManager(func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult {
		return credentialValidationResult{}
	})
	account := &Account{
		Username: "user",
		Password: "pass-US-{sid-24}",
	}
	user := &protocol.MemoryUser{Account: account}
	server := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	outbound := &session.Outbound{Tag: "US_OUT"}
	inbound := &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	}
	poolKey := "US_OUT\x00" + account.Username + "\x00" + account.Password
	manager.pools[poolKey] = &verifiedCredentialPool{
		expectedCountry: "US",
		server:          server.Destination,
		usernameTpl:     account.Username,
		passwordTpl:     account.Password,
		credentials: []socksCredential{
			{username: "user", password: "pass-US-verified"},
		},
	}

	first := manager.resolve(context.Background(), user, inbound, outbound, server, account).Account.(*Account)
	if first.Password != "pass-US-verified" {
		t.Fatalf("expected verified pool credential, got %q", first.Password)
	}

	second := manager.resolve(context.Background(), user, inbound, outbound, server, account).Account.(*Account)
	if second.Password != first.Password {
		t.Fatalf("expected bound credential to be reused, got %q and %q", first.Password, second.Password)
	}
}

func TestCredentialPoolFallsBackWithoutWaitingForValidation(t *testing.T) {
	validatorStarted := make(chan struct{})
	var startedOnce sync.Once
	manager := newTestCredentialPoolManager(func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult {
		startedOnce.Do(func() {
			close(validatorStarted)
			time.Sleep(200 * time.Millisecond)
		})
		return credentialValidationResult{ok: true}
	})
	account := &Account{
		Username: "user",
		Password: "pass-US-{sid-24}",
	}
	user := &protocol.MemoryUser{Account: account}
	server := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	inbound := &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	}

	start := time.Now()
	resolved := manager.resolve(context.Background(), user, inbound, &session.Outbound{Tag: "US_OUT"}, server, account).Account.(*Account)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected empty pool fallback not to wait for validation, took %s", elapsed)
	}
	if resolved.Password == account.Password {
		t.Fatalf("expected fallback credential to be generated, got template %q", resolved.Password)
	}

	select {
	case <-validatorStarted:
	case <-time.After(time.Second):
		t.Fatal("expected background validation to start")
	}
}

func TestCredentialPoolBlockReturnsInvalidCredential(t *testing.T) {
	manager := newTestCredentialPoolManager(nil)
	account := &Account{
		Username: "user",
		Password: "pass-US-{sid-24}",
	}
	user := &protocol.MemoryUser{Account: account}
	server := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	outbound := &session.Outbound{Tag: "US_OUT"}
	inbound := &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	}
	poolKey := "US_OUT\x00" + account.Username + "\x00" + account.Password
	manager.pools[poolKey] = &verifiedCredentialPool{
		expectedCountry: "US",
		server:          server.Destination,
		usernameTpl:     account.Username,
		passwordTpl:     account.Password,
		blocked:         true,
	}
	bindingKey := "203.0.113.10|US_OUT\x00" + account.Username + "\x00" + account.Password
	manager.bound[bindingKey] = &boundCredential{
		credential: socksCredential{username: "user", password: "pass-US-cached"},
		lastAccess: time.Now(),
	}

	resolved := manager.resolve(context.Background(), user, inbound, outbound, server, account).Account.(*Account)
	if resolved.Username == account.Username || resolved.Password == account.Password {
		t.Fatalf("expected blocked pool to return invalid credentials, got %q/%q", resolved.Username, resolved.Password)
	}
	if !strings.HasPrefix(resolved.Username, "blocked-") || !strings.HasPrefix(resolved.Password, "blocked-") {
		t.Fatalf("expected blocked credentials, got %q/%q", resolved.Username, resolved.Password)
	}
}

func TestCredentialPoolValidatorBlockMarksPoolBlocked(t *testing.T) {
	manager := newTestCredentialPoolManager(func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult {
		return credentialValidationResult{block: true}
	})
	account := &Account{
		Username: "user",
		Password: "pass-US-{sid-24}",
	}
	user := &protocol.MemoryUser{Account: account}
	server := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	poolKey := "US_OUT\x00" + account.Username + "\x00" + account.Password
	manager.pools[poolKey] = &verifiedCredentialPool{
		expectedCountry: "US",
		server:          server.Destination,
		usernameTpl:     account.Username,
		passwordTpl:     account.Password,
		credentials: []socksCredential{
			{username: "user", password: "pass-US-verified"},
		},
	}

	manager.fillPool(poolKey)

	pool := manager.pools[poolKey]
	if !pool.blocked {
		t.Fatal("expected block validation result to mark pool blocked")
	}
	if len(pool.credentials) != 0 {
		t.Fatalf("expected blocked pool credentials to be cleared, got %d", len(pool.credentials))
	}
}

func TestCredentialPoolValidatorPanicIsValidationFailure(t *testing.T) {
	manager := newTestCredentialPoolManager(func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult {
		panic("validation service exploded")
	})
	account := &Account{
		Username: "user",
		Password: "pass-US-{sid-24}",
	}
	user := &protocol.MemoryUser{Account: account}
	server := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	poolKey := "US_OUT\x00" + account.Username + "\x00" + account.Password
	manager.pools[poolKey] = &verifiedCredentialPool{
		expectedCountry: "US",
		server:          server.Destination,
		usernameTpl:     account.Username,
		passwordTpl:     account.Password,
		filling:         true,
	}

	manager.fillPool(poolKey)

	pool := manager.pools[poolKey]
	if pool.filling {
		t.Fatal("expected filling flag to be reset after validator panic")
	}
	if pool.blocked {
		t.Fatal("expected validator panic not to mark pool blocked")
	}
	if len(pool.credentials) != 0 {
		t.Fatalf("expected validator panic not to add credentials, got %d", len(pool.credentials))
	}
}

func TestCredentialPoolCleansIdleBindings(t *testing.T) {
	manager := newTestCredentialPoolManager(nil)
	now := time.Now()
	manager.bound["expired"] = &boundCredential{
		credential: socksCredential{username: "old"},
		lastAccess: now.Add(-boundCredentialIdleTTL - time.Nanosecond),
	}
	manager.bound["active"] = &boundCredential{
		credential: socksCredential{username: "active"},
		lastAccess: now.Add(-boundCredentialIdleTTL + time.Nanosecond),
	}

	manager.cleanupExpiredBoundCredentials(now)

	if _, found := manager.bound["expired"]; found {
		t.Fatal("expected expired binding to be removed")
	}
	if _, found := manager.bound["active"]; !found {
		t.Fatal("expected active binding to remain")
	}
}

func TestExpectedCountryFromOutbound(t *testing.T) {
	testCases := []struct {
		name      string
		tag       string
		country   string
		canVerify bool
	}{
		{name: "country tag", tag: "US_OUT", country: "US", canVerify: true},
		{name: "free tag", tag: "FREE_OUT", canVerify: false},
		{name: "no separator", tag: "US", canVerify: false},
		{name: "lowercase", tag: "us_OUT", canVerify: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			country, canVerify := expectedCountryFromOutbound(&session.Outbound{Tag: tc.tag})
			if country != tc.country || canVerify != tc.canVerify {
				t.Fatalf("expected (%q, %v), got (%q, %v)", tc.country, tc.canVerify, country, canVerify)
			}
		})
	}
}

func TestEvaluateCredentialValidationResponse(t *testing.T) {
	verifyTrue := true
	verifyFalse := false

	testCases := []struct {
		name     string
		response credentialValidationResponse
		expected credentialValidationResult
	}{
		{
			name:     "old response defaults to verify country",
			response: credentialValidationResponse{Country: "us"},
			expected: credentialValidationResult{ok: true},
		},
		{
			name:     "old response rejects mismatched country",
			response: credentialValidationResponse{Country: "in"},
			expected: credentialValidationResult{},
		},
		{
			name:     "verify true checks country",
			response: credentialValidationResponse{Country: "us", Verify: &verifyTrue},
			expected: credentialValidationResult{ok: true},
		},
		{
			name:     "verify false skips country",
			response: credentialValidationResponse{Country: "in", Verify: &verifyFalse},
			expected: credentialValidationResult{ok: true},
		},
		{
			name:     "block wins",
			response: credentialValidationResponse{Country: "us", Verify: &verifyFalse, Block: true},
			expected: credentialValidationResult{block: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluateCredentialValidationResponse(tc.response, "US")
			if result != tc.expected {
				t.Fatalf("expected %+v, got %+v", tc.expected, result)
			}
		})
	}
}

func newTestCredentialPoolManager(validator credentialValidator) *credentialPoolManager {
	if validator == nil {
		validator = func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult {
			return credentialValidationResult{}
		}
	}
	return &credentialPoolManager{
		bound:     make(map[string]*boundCredential),
		pools:     make(map[string]*verifiedCredentialPool),
		validator: validator,
	}
}
