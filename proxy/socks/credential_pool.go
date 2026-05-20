package socks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/net/proxy"
)

const (
	boundCredentialIdleTTL        = 5 * time.Hour
	verifiedCredentialPoolTarget  = 8
	verifiedCredentialMaxAttempts = 32
	credentialValidationTimeout   = 10 * time.Second
	credentialValidationURL       = "https://gitlab.520531.xyz/get-code"
)

type socksCredential struct {
	username string
	password string
}

type boundCredential struct {
	credential socksCredential
	lastAccess time.Time
}

type verifiedCredentialPool struct {
	expectedCountry string
	server          xnet.Destination
	usernameTpl     string
	passwordTpl     string
	credentials     []socksCredential
	filling         bool
	blocked         bool
}

type credentialValidationResult struct {
	ok    bool
	block bool
}

type credentialValidationResponse struct {
	Country string `json:"country"`
	Verify  *bool  `json:"verify"`
	Block   bool   `json:"block"`
}

type credentialValidator func(context.Context, xnet.Destination, socksCredential, string) credentialValidationResult

type credentialPoolManager struct {
	mutex     sync.Mutex
	bound     map[string]*boundCredential
	pools     map[string]*verifiedCredentialPool
	validator credentialValidator
}

func newCredentialPoolManager() *credentialPoolManager {
	m := &credentialPoolManager{
		bound:     make(map[string]*boundCredential),
		pools:     make(map[string]*verifiedCredentialPool),
		validator: validateSocksCredentialCountry,
	}
	go m.cleanupLoop()
	return m
}

var socksCredentialPools = newCredentialPoolManager()

func (m *credentialPoolManager) resolve(ctx context.Context, user *protocol.MemoryUser, inbound *session.Inbound, outbound *session.Outbound, server *protocol.ServerSpec, account *Account) *protocol.MemoryUser {
	scopeKey := outboundScopeKey(outbound, server)
	if scopeKey == "" {
		return cloneUserWithCredential(user, account, generateFreshCredential(account))
	}

	bindingKey := inbound.Source.Address.String() + "|" + scopeKey + "\x00" + account.Username + "\x00" + account.Password
	now := time.Now()
	expectedCountry, canVerify := expectedCountryFromOutbound(outbound)
	poolKey := scopeKey + "\x00" + account.Username + "\x00" + account.Password

	m.mutex.Lock()
	if canVerify {
		if pool := m.poolLocked(poolKey, expectedCountry, server, account); pool != nil && pool.blocked {
			credential := generateInvalidCredential()
			m.bound[bindingKey] = &boundCredential{
				credential: credential,
				lastAccess: now,
			}
			m.mutex.Unlock()
			return cloneUserWithCredential(user, account, credential)
		}
	}
	if cached, found := m.bound[bindingKey]; found {
		if now.Sub(cached.lastAccess) < boundCredentialIdleTTL {
			cached.lastAccess = now
			credential := cached.credential
			m.mutex.Unlock()
			if canVerify {
				m.ensureFill(poolKey, expectedCountry, server, account)
			}
			return cloneUserWithCredential(user, account, credential)
		}
		delete(m.bound, bindingKey)
	}

	var credential socksCredential
	if canVerify {
		if pool := m.poolLocked(poolKey, expectedCountry, server, account); pool != nil {
			if pool.blocked {
				credential = generateInvalidCredential()
			} else if len(pool.credentials) > 0 {
				credential = pool.credentials[0]
				pool.credentials = pool.credentials[1:]
			}
		}
	}
	if credential == (socksCredential{}) {
		credential = generateFreshCredential(account)
	}
	m.bound[bindingKey] = &boundCredential{
		credential: credential,
		lastAccess: now,
	}
	m.mutex.Unlock()

	if canVerify {
		m.ensureFill(poolKey, expectedCountry, server, account)
	}

	return cloneUserWithCredential(user, account, credential)
}

func (m *credentialPoolManager) ensureFill(poolKey, expectedCountry string, server *protocol.ServerSpec, account *Account) {
	if expectedCountry == "" || server == nil {
		return
	}

	m.mutex.Lock()
	pool := m.poolLocked(poolKey, expectedCountry, server, account)
	if pool == nil || pool.blocked || pool.filling || len(pool.credentials) >= verifiedCredentialPoolTarget {
		m.mutex.Unlock()
		return
	}
	pool.filling = true
	m.mutex.Unlock()

	go m.fillPool(poolKey)
}

func (m *credentialPoolManager) poolLocked(poolKey, expectedCountry string, server *protocol.ServerSpec, account *Account) *verifiedCredentialPool {
	if expectedCountry == "" || server == nil {
		return nil
	}
	pool := m.pools[poolKey]
	if pool == nil {
		pool = &verifiedCredentialPool{
			expectedCountry: strings.ToUpper(expectedCountry),
			server:          server.Destination,
			usernameTpl:     account.Username,
			passwordTpl:     account.Password,
		}
		m.pools[poolKey] = pool
	}
	return pool
}

func (m *credentialPoolManager) fillPool(poolKey string) {
	defer func() {
		_ = recover()
		m.mutex.Lock()
		if pool := m.pools[poolKey]; pool != nil {
			pool.filling = false
		}
		m.mutex.Unlock()
	}()

	for attempts := 0; attempts < verifiedCredentialMaxAttempts; attempts++ {
		m.mutex.Lock()
		pool := m.pools[poolKey]
		if pool == nil || pool.blocked || len(pool.credentials) >= verifiedCredentialPoolTarget {
			m.mutex.Unlock()
			return
		}
		expectedCountry := pool.expectedCountry
		server := pool.server
		account := &Account{Username: pool.usernameTpl, Password: pool.passwordTpl}
		m.mutex.Unlock()

		credential := generateFreshCredential(account)
		ctx, cancel := context.WithTimeout(context.Background(), credentialValidationTimeout)
		result := m.validateCredential(ctx, server, credential, expectedCountry)
		cancel()
		if result.block {
			m.mutex.Lock()
			if pool := m.pools[poolKey]; pool != nil {
				pool.blocked = true
				pool.credentials = nil
			}
			m.mutex.Unlock()
			return
		}
		if !result.ok {
			continue
		}

		m.mutex.Lock()
		pool = m.pools[poolKey]
		if pool != nil && len(pool.credentials) < verifiedCredentialPoolTarget {
			pool.credentials = append(pool.credentials, credential)
		}
		m.mutex.Unlock()
	}
}

func (m *credentialPoolManager) validateCredential(ctx context.Context, server xnet.Destination, credential socksCredential, expectedCountry string) (result credentialValidationResult) {
	defer func() {
		if recover() != nil {
			result = credentialValidationResult{}
		}
	}()
	return m.validator(ctx, server, credential, expectedCountry)
}

func (m *credentialPoolManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanupExpiredBoundCredentials(time.Now())
	}
}

func (m *credentialPoolManager) cleanupExpiredBoundCredentials(now time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for bindingKey, cached := range m.bound {
		if now.Sub(cached.lastAccess) >= boundCredentialIdleTTL {
			delete(m.bound, bindingKey)
		}
	}
}

func generateFreshCredential(account *Account) socksCredential {
	credential := socksCredential{
		username: account.Username,
		password: account.Password,
	}
	if dynamicUsernameGen.HasBoundDynamicPattern(credential.username) {
		credential.username = dynamicUsernameGen.GenerateFreshUsername(credential.username)
	}
	if dynamicUsernameGen.HasBoundDynamicPattern(credential.password) {
		credential.password = dynamicUsernameGen.GenerateFreshUsername(credential.password)
	}
	return credential
}

func generateInvalidCredential() socksCredential {
	return socksCredential{
		username: "blocked-" + randomHex(16),
		password: "blocked-" + randomHex(16),
	}
}

func randomHex(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return time.Now().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

func cloneUserWithCredential(user *protocol.MemoryUser, account *Account, credential socksCredential) *protocol.MemoryUser {
	clonedUser := *user
	clonedAccount := *account
	clonedAccount.Username = credential.username
	clonedAccount.Password = credential.password
	clonedUser.Account = &clonedAccount
	return &clonedUser
}

func outboundScopeKey(outbound *session.Outbound, server *protocol.ServerSpec) string {
	if outbound != nil && outbound.Tag != "" {
		return outbound.Tag
	}
	if server != nil {
		return server.Destination.String()
	}
	return ""
}

func expectedCountryFromOutbound(outbound *session.Outbound) (string, bool) {
	if outbound == nil {
		return "", false
	}
	idx := strings.IndexByte(outbound.Tag, '_')
	if idx != 2 {
		return "", false
	}
	country := outbound.Tag[:idx]
	for _, r := range country {
		if r < 'A' || r > 'Z' {
			return "", false
		}
	}
	return country, true
}

func validateSocksCredentialCountry(ctx context.Context, server xnet.Destination, credential socksCredential, expectedCountry string) (result credentialValidationResult) {
	defer func() {
		if recover() != nil {
			result = credentialValidationResult{}
		}
	}()

	auth := &proxy.Auth{
		User:     credential.username,
		Password: credential.password,
	}
	forward := &net.Dialer{Timeout: credentialValidationTimeout}
	dialer, err := proxy.SOCKS5(server.Network.SystemString(), server.NetAddr(), auth, forward)
	if err != nil {
		return credentialValidationResult{}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			type dialResult struct {
				conn net.Conn
				err  error
			}
			done := make(chan dialResult, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- dialResult{err: fmt.Errorf("socks validation dial panic: %v", r)}
					}
				}()
				conn, err := dialer.Dial(network, address)
				done <- dialResult{conn: conn, err: err}
			}()
			select {
			case <-ctx.Done():
				go func() {
					result := <-done
					if result.conn != nil {
						_ = result.conn.Close()
					}
				}()
				return nil, ctx.Err()
			case result := <-done:
				return result.conn, result.err
			}
		},
		TLSHandshakeTimeout:   credentialValidationTimeout,
		ResponseHeaderTimeout: credentialValidationTimeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   credentialValidationTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, credentialValidationURL, nil)
	if err != nil {
		return credentialValidationResult{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return credentialValidationResult{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return credentialValidationResult{}
	}

	var response credentialValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return credentialValidationResult{}
	}
	return evaluateCredentialValidationResponse(response, expectedCountry)
}

func evaluateCredentialValidationResponse(result credentialValidationResponse, expectedCountry string) credentialValidationResult {
	if result.Block {
		return credentialValidationResult{block: true}
	}
	if result.Verify == nil || *result.Verify {
		return credentialValidationResult{ok: strings.EqualFold(result.Country, expectedCountry)}
	}
	return credentialValidationResult{ok: true}
}
