package socks

import (
	"context"
	"regexp"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestResolveUserBoundUserAppliesWithoutUserBindTag(t *testing.T) {
	user := &protocol.MemoryUser{
		Account: &Account{
			Username: "user_{sid-24}",
			Password: "pass_{did-24}",
		},
		Level: 1,
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "regular-inbound",
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	})
	outbound := &session.Outbound{Tag: "residential-out"}

	first := resolveUserBoundUser(ctx, user, outbound, nil)
	second := resolveUserBoundUser(ctx, user, outbound, nil)

	firstAccount := first.Account.(*Account)
	secondAccount := second.Account.(*Account)
	if firstAccount.Username != secondAccount.Username {
		t.Fatalf("expected same source IP and outbound to reuse username, got %q and %q", firstAccount.Username, secondAccount.Username)
	}
	if firstAccount.Password != secondAccount.Password {
		t.Fatalf("expected same source IP and outbound to reuse password, got %q and %q", firstAccount.Password, secondAccount.Password)
	}

	if firstAccount.Username == "user_{sid-24}" || firstAccount.Password == "pass_{did-24}" {
		t.Fatalf("expected dynamic credentials to be expanded, got username %q and password %q", firstAccount.Username, firstAccount.Password)
	}
	if user.Account.(*Account).Username != "user_{sid-24}" {
		t.Fatalf("expected original account template to remain unchanged, got %q", user.Account.(*Account).Username)
	}

	assertMatches(t, firstAccount.Username, `^user_[a-zA-Z0-9]{24}$`)
	assertMatches(t, firstAccount.Password, `^pass_[0-9]{24}$`)
}

func TestResolveUserBoundUserSeparatesOutboundScopes(t *testing.T) {
	user := &protocol.MemoryUser{
		Account: &Account{
			Username: "user_{sid-24}",
			Password: "pass_{did-24}",
		},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "regular-inbound",
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	})

	first := resolveUserBoundUser(ctx, user, &session.Outbound{Tag: "outbound-1"}, nil).Account.(*Account)
	second := resolveUserBoundUser(ctx, user, &session.Outbound{Tag: "outbound-2"}, nil).Account.(*Account)

	if first.Username == second.Username {
		t.Fatalf("expected same source IP with different outbound tags to get different usernames, got %q", first.Username)
	}
	if first.Password == second.Password {
		t.Fatalf("expected same source IP with different outbound tags to get different passwords, got %q", first.Password)
	}
}

func TestResolveUserBoundUserFallsBackToServerScope(t *testing.T) {
	user := &protocol.MemoryUser{
		Account: &Account{Username: "user_{sid-24}"},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	})
	firstServer := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 1080), user)
	secondServer := protocol.NewServerSpec(xnet.TCPDestination(xnet.ParseAddress("198.51.100.2"), 1080), user)

	first := resolveUserBoundUser(ctx, user, &session.Outbound{}, firstServer).Account.(*Account)
	second := resolveUserBoundUser(ctx, user, &session.Outbound{}, secondServer).Account.(*Account)

	if first.Username == second.Username {
		t.Fatalf("expected server destination fallback to separate bound usernames, got %q", first.Username)
	}
}

func TestResolveUserBoundUserSkipsStaticAccount(t *testing.T) {
	user := &protocol.MemoryUser{
		Account: &Account{
			Username: "static-user",
			Password: "static-pass",
		},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "FREE_IN",
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 12345),
	})

	resolved := resolveUserBoundUser(ctx, user, &session.Outbound{Tag: "FREE_OUT"}, nil)
	if resolved != user {
		t.Fatal("expected static account to bypass binding and pool logic")
	}
}

func assertMatches(t *testing.T, value, pattern string) {
	t.Helper()
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		t.Fatalf("invalid regex %q: %v", pattern, err)
	}
	if !matched {
		t.Fatalf("value %q does not match %q", value, pattern)
	}
}
