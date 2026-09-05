// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hscontrol

import (
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// nodePeerVisibleEqual reports whether two snapshots of the same node differ
// in anything a peer could observe in its netmap.
//
// LastSeen, the gorm timestamps and the in-memory poll-session bookkeeping
// are deliberately ignored. The cylonix manager refreshes LastSeen on every
// WireGuard gateway heartbeat through the UpdateNode RPC, and broadcasting a
// "node added" for that alone fanned a byte-identical node out to every
// visible peer every ~20s per gateway.
func nodePeerVisibleEqual(a, b *types.Node) bool {
	if a == nil || b == nil {
		return a == b
	}

	if a.MachineKey != b.MachineKey || a.NodeKey != b.NodeKey || a.DiscoKey != b.DiscoKey {
		return false
	}

	if a.Hostname != b.Hostname || a.GivenName != b.GivenName {
		return false
	}

	if !ptrEqual(a.UserID, b.UserID) || !slices.Equal(a.Tags, b.Tags) {
		return false
	}

	if !ptrEqual(a.IPv4, b.IPv4) || !ptrEqual(a.IPv6, b.IPv6) {
		return false
	}

	if !slices.Equal(a.Endpoints, b.Endpoints) {
		return false
	}

	if !hostinfoEqualNilSafe(a.Hostinfo, b.Hostinfo) {
		return false
	}

	if !timePtrEqual(a.Expiry, b.Expiry) {
		return false
	}

	if !slices.Equal(a.ApprovedRoutes, b.ApprovedRoutes) {
		return false
	}

	if !ptrEqual(a.IsOnline, b.IsOnline) {
		return false
	}

	if !ptrEqual(a.IsWireguardOnly, b.IsWireguardOnly) ||
		!ptrEqual(a.StableID, b.StableID) ||
		a.Namespace != b.Namespace ||
		a.NetworkDomain != b.NetworkDomain ||
		!ptrEqual(a.CapVersion, b.CapVersion) {
		return false
	}

	return capabilityNamesEqual(a.Capabilities, b.Capabilities)
}

func ptrEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Equal(*b)
}

func hostinfoEqualNilSafe(a, b *tailcfg.Hostinfo) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Equal(b)
}

func capabilityNamesEqual(a, b []types.Capability) bool {
	if len(a) != len(b) {
		return false
	}

	an := make([]string, 0, len(a))
	for _, c := range a {
		an = append(an, c.Name)
	}

	bn := make([]string, 0, len(b))
	for _, c := range b {
		bn = append(bn, c.Name)
	}

	slices.Sort(an)
	slices.Sort(bn)

	return slices.Equal(an, bn)
}
