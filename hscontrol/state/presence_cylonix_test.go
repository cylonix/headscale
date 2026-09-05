// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/ptr"
)

func TestDecidePresence(t *testing.T) {
	ep1 := netip.MustParseAddrPort("203.0.113.9:41641")
	ep2 := netip.MustParseAddrPort("198.51.100.4:41641")

	offline := &types.Node{IsOnline: ptr.To(false), Endpoints: []netip.AddrPort{ep1}}
	online := &types.Node{IsOnline: ptr.To(true), Endpoints: []netip.AddrPort{ep1}}
	unknown := &types.Node{Endpoints: []netip.AddrPort{ep1}}

	// Heartbeat repeating the current state is a no-op.
	require.True(t, decidePresence(online, ptr.To(true), []netip.AddrPort{ep1}, true).isNoop())
	require.True(t, decidePresence(offline, ptr.To(false), []netip.AddrPort{ep1}, true).isNoop())
	// Not asking about presence at all is a no-op.
	require.True(t, decidePresence(online, nil, nil, false).isNoop())

	// Transitions.
	up := decidePresence(offline, ptr.To(true), nil, false)
	require.True(t, up.OnlineChanged)
	require.True(t, up.WentOnline)
	require.False(t, up.EndpointsChanged)

	down := decidePresence(online, ptr.To(false), nil, false)
	require.True(t, down.OnlineChanged)
	require.False(t, down.WentOnline)

	// A nil IsOnline (never announced) counts as offline.
	first := decidePresence(unknown, ptr.To(true), nil, false)
	require.True(t, first.OnlineChanged)
	require.True(t, first.WentOnline)

	// Endpoint change without a presence change.
	moved := decidePresence(online, ptr.To(true), []netip.AddrPort{ep2}, true)
	require.False(t, moved.OnlineChanged)
	require.True(t, moved.EndpointsChanged)

	// Empty endpoints list with hasEndpoints clears them; without the flag it
	// leaves them alone.
	cleared := decidePresence(online, nil, nil, true)
	require.True(t, cleared.EndpointsChanged)
	require.True(t, decidePresence(online, nil, nil, false).isNoop())
}
