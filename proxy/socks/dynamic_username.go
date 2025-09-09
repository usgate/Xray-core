package socks

import (
	"github.com/xtls/xray-core/common/username"
)

// For backward compatibility, re-export the types and functions from the common username package
type DynamicUsernameGenerator = username.DynamicUsernameGenerator
type UsernameCache = username.UsernameCache

// NewDynamicUsernameGenerator creates a new dynamic username generator
// Deprecated: Use username.NewDynamicUsernameGenerator() or username.GetGlobalDynamicUsernameGenerator() instead
func NewDynamicUsernameGenerator() *DynamicUsernameGenerator {
	return username.NewDynamicUsernameGenerator()
}
