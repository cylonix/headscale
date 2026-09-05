// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hscontrol

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func sampleNode() *types.Node {
	uid := uint(7)
	v4 := netip.MustParseAddr("100.64.0.9")
	online := true
	seen := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	return &types.Node{
		ID:        9,
		Hostname:  "wg-ca-17-v2",
		GivenName: "wg-ca-17-v2",
		UserID:    &uid,
		IPv4:      &v4,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")},
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "wg-ca-17-v2", RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}},
		LastSeen:  &seen,
		IsOnline:  &online,
		UpdatedAt: seen,
		Namespace: "acme",
		Capabilities: []types.Capability{
			{Name: "relay"},
			{Name: "exit"},
		},
	}
}

func TestNodePeerVisibleEqualIgnoresHeartbeatFields(t *testing.T) {
	a := sampleNode()
	b := sampleNode()

	later := a.LastSeen.Add(20 * time.Second)
	b.LastSeen = &later
	b.UpdatedAt = later
	b.SessionEpoch = 42
	b.ActiveSessions = 3
	// Capability order must not matter.
	b.Capabilities = []types.Capability{{Name: "exit"}, {Name: "relay"}}

	require.True(t, nodePeerVisibleEqual(a, b),
		"LastSeen/timestamps/session bookkeeping/capability order are not peer-visible")
}

func TestNodePeerVisibleEqualDetectsVisibleChanges(t *testing.T) {
	base := sampleNode()

	endpoints := sampleNode()
	endpoints.Endpoints = append(endpoints.Endpoints, netip.MustParseAddrPort("198.51.100.4:41641"))
	require.False(t, nodePeerVisibleEqual(base, endpoints), "endpoints")

	offline := sampleNode()
	off := false
	offline.IsOnline = &off
	require.False(t, nodePeerVisibleEqual(base, offline), "online flag")

	routes := sampleNode()
	routes.Hostinfo = &tailcfg.Hostinfo{Hostname: "wg-ca-17-v2"}
	require.False(t, nodePeerVisibleEqual(base, routes), "hostinfo routes")

	caps := sampleNode()
	caps.Capabilities = []types.Capability{{Name: "relay"}}
	require.False(t, nodePeerVisibleEqual(base, caps), "capabilities")

	renamed := sampleNode()
	renamed.GivenName = "wg-ca-17-v3"
	require.False(t, nodePeerVisibleEqual(base, renamed), "given name")

	require.False(t, nodePeerVisibleEqual(base, nil))
	require.True(t, nodePeerVisibleEqual(nil, nil))
}
