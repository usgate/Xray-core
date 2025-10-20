package socks

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
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

// GetEffectivePassword returns the effective password, generating dynamic parts if needed
func (a *Account) GetEffectivePassword() string {
	if dynamicUsernameGen.HasDynamicPattern(a.Password) {
		return dynamicUsernameGen.GenerateUsername(a.Password)
	}
	return a.Password
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
