package socks

import (
	"context"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/username"
)

var dynamicUsernameGen = username.GetGlobalDynamicUsernameGenerator()

// GetEffectiveUsername returns the effective username, generating dynamic parts if needed
func (a *Account) GetEffectiveUsername() string {
	if dynamicUsernameGen.HasDynamicPattern(a.Username) {
		return dynamicUsernameGen.GenerateUsername(a.Username)
	}
	return a.Username
}

// GetEffectiveUsernameWithContext returns the effective username with context for IP-based generation
func (a *Account) GetEffectiveUsernameWithContext(ctx context.Context) string {
	if !dynamicUsernameGen.HasDynamicPattern(a.Username) {
		return a.Username
	}

	// Try to get client IP from context
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		clientIP := inbound.Source.Address.String()
		if clientIP != "" {
			// Use IP-based generation if patterns contain ip-based placeholders
			return dynamicUsernameGen.GenerateUsernameWithIP(a.Username, clientIP)
		}
	}

	// Fallback to regular generation
	return dynamicUsernameGen.GenerateUsername(a.Username)
}

func (a *Account) Equals(another protocol.Account) bool {
	if account, ok := another.(*Account); ok {
		// For dynamic usernames, we compare the template, not the generated value
		return a.Username == account.Username
	}
	return false
}

func (a *Account) ToProto() proto.Message {
	return a
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return a, nil
}

func (c *ServerConfig) HasAccount(username, password string) bool {
	if c.Accounts == nil {
		return false
	}
	storedPassed, found := c.Accounts[username]
	if !found {
		return false
	}
	return storedPassed == password
}
