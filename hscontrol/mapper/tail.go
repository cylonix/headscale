package mapper

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/samber/lo"
	"tailscale.com/tailcfg"
)

func tailNodes(
	nodes types.Nodes,
	capVer tailcfg.CapabilityVersion,
	pol *policy.ACLPolicy,
	cfg *types.Config,
) ([]*tailcfg.Node, error) {
	tNodes := make([]*tailcfg.Node, len(nodes))

	for index, node := range nodes {
		node, err := tailNode(
			node,
			capVer,
			pol,
			cfg,
		)
		if err != nil {
			return nil, err
		}

		tNodes[index] = node
	}

	return tNodes, nil
}

// tailNode converts a Node into a Tailscale Node.
func tailNode(
	node *types.Node,
	clientCapVer tailcfg.CapabilityVersion, // client's capability version __CYLONIX_MOD__
	pol *policy.ACLPolicy,
	cfg *types.Config,
) (*tailcfg.Node, error) {
	addrs := node.Prefixes()

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	primaryPrefixes := []netip.Prefix{}

	for _, route := range node.Routes {
		if route.Enabled {
			if route.IsPrimary {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
				primaryPrefixes = append(primaryPrefixes, netip.Prefix(route.Prefix))
			} else if route.IsExitRoute() {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
			}
		}
	}

	var derp int
	if node.Hostinfo != nil && node.Hostinfo.NetInfo != nil {
		derp = node.Hostinfo.NetInfo.PreferredDERP
	} else {
		derp = 0 // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if node.Expiry != nil {
		keyExpiry = *node.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	hostname, err := node.GetFQDN(cfg, cfg.BaseDomain)
	if err != nil {
		return nil, fmt.Errorf("tailNode, failed to create FQDN: %s", err)
	}

	tags, _ := pol.TagsOfNode(node)
	tags = lo.Uniq(append(tags, node.ForcedTags...))
	policyNodeAttrs, err := pol.NodeAttrsOfNode(node)
	if err != nil {
		return nil, fmt.Errorf("tailNode, failed to resolve nodeAttrs: %w", err)
	}

	// __BEGIN_CYLONIX_ADD__
	stableID := node.ID.StableID()
	if node.StableID != nil {
		stableID = tailcfg.StableNodeID(*node.StableID)
	}
	nodeCapVer := tailcfg.CapabilityVersion(0)
	if node.CapVersion != nil {
		nodeCapVer = tailcfg.CapabilityVersion(*node.CapVersion)
	}
	isWireguardOnly := node.DiscoKey.IsZero()
	if !isWireguardOnly && node.IsWireguardOnly != nil {
		isWireguardOnly = *node.IsWireguardOnly
	}
	// __END_CYLONIX_ADD__

	tNode := tailcfg.Node{
		ID:       tailcfg.NodeID(node.ID), // this is the actual ID
		StableID: stableID,                // __CYLONIX_MOD__
		Name:     hostname,
		Cap:      nodeCapVer, // __CYLONIX_MOD__

		User: tailcfg.UserID(node.UserID),

		Key:       node.NodeKey,
		KeyExpiry: keyExpiry.UTC(),

		Machine:    node.MachineKey,
		DiscoKey:   node.DiscoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  node.Endpoints,
		HomeDERP:   derp,
		Hostinfo:   node.Hostinfo.View(),
		Created:    node.CreatedAt.UTC(),

		Online: node.IsOnline,

		Tags: tags,

		PrimaryRoutes: primaryPrefixes,

		MachineAuthorized: !node.IsExpired(),
		Expired:           node.IsExpired(),

		IsWireGuardOnly: isWireguardOnly, // __CYLONIX_MOD__
		IsJailed:        node.IsJailed,   // __CYLONIX_ADD__
	}

	//   - 74: 2023-09-18: Client understands NodeCapMap
	if clientCapVer >= 74 { // __CYLONIX_MOD__
		tNode.CapMap = tailcfg.NodeCapMap{
			tailcfg.CapabilityFileSharing: []tailcfg.RawMessage{},
			tailcfg.CapabilityAdmin:       []tailcfg.RawMessage{},
			tailcfg.CapabilitySSH:         []tailcfg.RawMessage{},
		}

		if cfg.RandomizeClientPort {
			tNode.CapMap[tailcfg.NodeAttrRandomizeClientPort] = []tailcfg.RawMessage{}
		}
		// __BEGIN_CYLONIX_ADD__
		if isWireguardOnly {
			// WireGuard-only nodes do not support default capabilities
			tNode.CapMap = tailcfg.NodeCapMap{}
		}
		for _, cap := range node.Capabilities {
			tNode.CapMap[tailcfg.NodeCapability(cap.Name)] = []tailcfg.RawMessage{}
		}
		for _, attr := range policyNodeAttrs {
			tNode.CapMap[attr] = []tailcfg.RawMessage{}
		}
		// __END_CYLONIX_ADD__
	} else {
		tNode.Capabilities = []tailcfg.NodeCapability{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
		}

		if cfg.RandomizeClientPort {
			tNode.Capabilities = append(tNode.Capabilities, tailcfg.NodeAttrRandomizeClientPort)
		}
		tNode.Capabilities = append(tNode.Capabilities, policyNodeAttrs...)
	}

	//   - 72: 2023-08-23: TS-2023-006 UPnP issue fixed; UPnP can now be used again
	if nodeCapVer < 72 { // __CYLONIX_MOD__
		tNode.Capabilities = append(tNode.Capabilities, tailcfg.NodeAttrDisableUPnP)
	}

	if node.IsOnline == nil || !*node.IsOnline {
		// LastSeen is only set when node is
		// not connected to the control server.
		tNode.LastSeen = node.LastSeen
	}

	return &tNode, nil
}
