package types

// Cylonix-added test: TailNode's StableID sanity guard. Legacy manager
// registrations persisted the all-zero UUID as the stable ID (device row ID
// not populated at write time), and several nodes share that value. The
// guard must fall back to the unique integer node ID for empty, whitespace,
// or zero-UUID stored values while honoring any other stored value.

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestTailNodeStableIDSanity(t *testing.T) {
	sp := func(s string) *string { return &s }
	cases := []struct {
		name   string
		stored *string
		want   tailcfg.StableNodeID
	}{
		{"nil-column-falls-back-to-node-id", nil, "7"},
		{"valid-uuid-honored", sp("019786c8-c6b7-73ba-9e0a-8af924a4d01f"), "019786c8-c6b7-73ba-9e0a-8af924a4d01f"},
		{"zero-uuid-falls-back-to-node-id", sp(zeroUUIDStableID), "7"},
		{"empty-falls-back-to-node-id", sp(""), "7"},
		{"whitespace-falls-back-to-node-id", sp("  "), "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &Node{
				ID:        7,
				GivenName: "stable-id-sanity",
				Hostinfo:  &tailcfg.Hostinfo{},
				StableID:  tc.stored,
			}
			cfg := &Config{
				TailcfgDNSConfig: &tailcfg.DNSConfig{},
				Taildrop:         TaildropConfig{Enabled: true},
			}
			tn, err := n.View().TailNode(
				0,
				func(id NodeID) []netip.Prefix { return nil },
				cfg,
			)
			if err != nil {
				t.Fatalf("TailNode() error = %v", err)
			}
			if tn.StableID != tc.want {
				t.Errorf("TailNode() StableID = %q, want %q", tn.StableID, tc.want)
			}
		})
	}
}
