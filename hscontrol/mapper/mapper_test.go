package mapper

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ptr"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
				},
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
					Hostname: hostname,
					UserID:   ptr.To(userid),
					User: &types.User{
						Name: username,
					},
				}
			}

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
				},
				nodeInShared1.View(),
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// mockState is a mock implementation that provides the required methods.
type mockState struct {
	polMan  policy.PolicyManager
	derpMap *tailcfg.DERPMap
	primary *routes.PrimaryRoutes
	nodes   types.Nodes
	peers   types.Nodes
}

func (m *mockState) DERPMap() *tailcfg.DERPMap {
	return m.derpMap
}

func (m *mockState) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if m.polMan == nil {
		return tailcfg.FilterAllowAll, nil
	}
	return m.polMan.Filter()
}

func (m *mockState) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	if m.polMan == nil {
		return nil, nil
	}
	return m.polMan.SSHPolicy(node)
}

func (m *mockState) NodeCanHaveTag(node types.NodeView, tag string) bool {
	if m.polMan == nil {
		return false
	}
	return m.polMan.NodeCanHaveTag(node, tag)
}

func (m *mockState) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	if m.primary == nil {
		return nil
	}
	return m.primary.PrimaryRoutes(nodeID)
}

func (m *mockState) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	if len(peerIDs) > 0 {
		// Filter peers by the provided IDs
		var filtered types.Nodes
		for _, peer := range m.peers {
			if slices.Contains(peerIDs, peer.ID) {
				filtered = append(filtered, peer)
			}
		}

		return filtered, nil
	}
	// Return all peers except the node itself
	var filtered types.Nodes
	for _, peer := range m.peers {
		if peer.ID != nodeID {
			filtered = append(filtered, peer)
		}
	}

	return filtered, nil
}

func (m *mockState) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	if len(nodeIDs) > 0 {
		// Filter nodes by the provided IDs
		var filtered types.Nodes
		for _, node := range m.nodes {
			if slices.Contains(nodeIDs, node.ID) {
				filtered = append(filtered, node)
			}
		}

		return filtered, nil
	}

	return m.nodes, nil
}

func Test_fullMapResponse(t *testing.T) {
	t.Skip("Test needs to be refactored for new state-based architecture")
	// TODO: Refactor this test to work with the new state-based mapper
	// The test architecture needs to be updated to work with the state interface
	// instead of the old direct dependency injection pattern
}

func TestParseVersion(t *testing.T) {
	major, minor, patch, err := parseVersion("1.80.4")
	assert.Nil(t, err)
	assert.Equal(t, 1, major)
	assert.Equal(t, 80, minor)
	assert.Equal(t, 4, patch)

	major, minor, patch, err = parseVersion("0.100.2")
	assert.Nil(t, err)
	assert.Equal(t, 0, major)
	assert.Equal(t, 100, minor)
	assert.Equal(t, 2, patch)

	_, _, _, err = parseVersion("1.2.3-4")
	assert.NotNil(t, err)

	_, _, _, err = parseVersion("1.2")
	assert.NotNil(t, err)

	_, _, _, err = parseVersion("abc.def.ghi")
	assert.NotNil(t, err)

	_, _, _, err = parseVersion("1.2.x")
	assert.NotNil(t, err)

	version := "1.80.4-extra-info"
	version = strings.SplitN(version, "-", 2)[0]
	major, minor, patch, err = parseVersion(version)
	assert.Nil(t, err)
	assert.Equal(t, 1, major)
	assert.Equal(t, 80, minor)
	assert.Equal(t, 4, patch)
}

// __BEGIN_CYLONIX_ADD__

func TestMergeDERPMapFromPolicy(t *testing.T) {
	global := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "nyc"},
		},
	}

	// Policy with a derpMap section (hujson: comments and trailing commas)
	// merges the tenant region over the global map.
	policyData := `{
		// tenant policy
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"derpMap": {
			"regions": {
				"903": {
					"regionID": 903,
					"regionCode": "cylonix-ca",
					"nodes": [{
						"name": "derp-ca-1",
						"regionID": 903,
						"hostName": "137.184.40.154",
					}],
				},
			},
		},
	}`
	merged, err := mergeDERPMapFromPolicy(policyData, global)
	assert.Nil(t, err)
	assert.NotNil(t, merged.Regions[1])
	assert.NotNil(t, merged.Regions[903])
	assert.Equal(t, "cylonix-ca", merged.Regions[903].RegionCode)
	assert.Len(t, merged.Regions[903].Nodes, 1)

	// The input map must not be mutated: WithDERPMap hands in a fresh
	// AsStruct copy, but derpMapForNode relies on merge not aliasing.
	assert.Nil(t, global.Regions[903])

	// Policy without a derpMap section returns the input unchanged.
	merged, err = mergeDERPMapFromPolicy(`{"acls": []}`, global)
	assert.Nil(t, err)
	assert.Equal(t, global, merged)

	// Empty policy data returns the input unchanged.
	merged, err = mergeDERPMapFromPolicy("", global)
	assert.Nil(t, err)
	assert.Equal(t, global, merged)

	// Invalid hujson errors out (callers fall back to the global map).
	_, err = mergeDERPMapFromPolicy("{not-valid", global)
	assert.NotNil(t, err)
}

// __END_CYLONIX_ADD__
