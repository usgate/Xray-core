package http

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

func (a *Account) Equals(another protocol.Account) bool {
	if account, ok := another.(*Account); ok {
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

func (sc *ServerConfig) HasAccount(username, password string) bool {
	if sc.Accounts == nil {
		return false
	}

	p, found := sc.Accounts[username]
	if !found {
		return false
	}
	return p == password
}
