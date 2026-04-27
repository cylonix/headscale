// __BEGIN_CYLONIX_MOD__
// Application-layer capability grants + per-node attribute assignments.
//
// These are upstream Tailscale ACL features that juanfont/headscale's policy
// v2 intentionally does not implement (the upstream maintainer positions
// headscale as a home-lab control plane and has declined multi-tenant/
// enterprise feature requests). Cylonix requires both features for taildrop
// and taildrive permission gating in a multi-tenant deployment:
//
//   Grants:    tailscale.com/cap/{taildrop,taildrive,taildrive-sharer}
//              compiled to tailcfg.FilterRule{SrcIPs, CapGrant[]}.
//   NodeAttrs: per-destination NodeCapability strings merged into the
//              Tailscale NodeCapMap.
//
// This file layers both onto v2 without modifying upstream v2/filter.go.
// Wire-up points:
//   * Policy has Grants + NodeAttrs fields (see types.go __CYLONIX_MOD__).
//   * PolicyManager.Filter() appends compileGrantRules output to the ACL
//     filter rules it returns.
//   * NodeView.TailNode() merges NodeAttrs for the current node into the
//     returned tailcfg.Node.CapMap.
//
// Syntax (HuJSON):
//
//   "grants": [
//     {
//       "src": ["group:sales"],
//       "dst": ["group:engineering"],
//       "app": {
//         "tailscale.com/cap/taildrop": [{}]
//       }
//     },
//     {
//       "src": ["tag:drive-user"],
//       "dst": ["tag:drive-server"],
//       "app": {
//         "tailscale.com/cap/taildrive": [{"shares": ["public"]}]
//       }
//     }
//   ],
//   "nodeAttrs": [
//     {
//       "target": ["autogroup:member"],
//       "attr":   ["randomize-client-port"]
//     }
//   ]
//
// The taildrive case is special: a forward grant
// (src=A dst=B app=taildrive) also implies a reverse grant
// (src=B dst=A app=taildrive-sharer) so the sharer-side can introspect
// mountable peers. compileGrantRules emits both FilterRules.

package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Grant is an application-capability grant rule.
type Grant struct {
	Sources      Aliases                                         `json:"src"`
	Destinations Aliases                                         `json:"dst"`
	App          map[tailcfg.PeerCapability][]tailcfg.RawMessage `json:"app"`
}

// Grants is a list of Grant rules.
type Grants []Grant

// Validate checks that the grant is well-formed. Called from Policy.validate().
func (g *Grant) Validate() error {
	if len(g.Sources) == 0 {
		return fmt.Errorf("grant: at least one source is required")
	}
	if len(g.Destinations) == 0 {
		return fmt.Errorf("grant: at least one destination is required")
	}
	if len(g.App) == 0 {
		return fmt.Errorf("grant: at least one app capability is required")
	}
	for _, a := range g.Sources {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("grant src: %w", err)
		}
	}
	for _, a := range g.Destinations {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("grant dst: %w", err)
		}
	}
	return nil
}

// NodeAttr is a per-node attribute assignment.
type NodeAttr struct {
	Target Aliases                  `json:"target"`
	Attr   []tailcfg.NodeCapability `json:"attr"`
}

// NodeAttrs is a list of NodeAttr rules.
type NodeAttrs []NodeAttr

// Validate checks that the node-attr rule is well-formed.
func (na *NodeAttr) Validate() error {
	if len(na.Target) == 0 {
		return fmt.Errorf("nodeAttrs: at least one target is required")
	}
	if len(na.Attr) == 0 {
		return fmt.Errorf("nodeAttrs: at least one attr is required")
	}
	for _, a := range na.Target {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("nodeAttrs target: %w", err)
		}
	}
	return nil
}

// UnmarshalJSON for Grants wraps each entry through AliasEnc handling so the
// src/dst fields accept the same strings as ACL sources/destinations.
func (g *Grants) UnmarshalJSON(b []byte) error {
	// The wire shape uses plain []string for src/dst (same as ACL.Sources/
	// Destinations). Aliases already has an UnmarshalJSON that handles that.
	type grantWire struct {
		Sources      Aliases                                         `json:"src"`
		Destinations Aliases                                         `json:"dst"`
		App          map[tailcfg.PeerCapability][]tailcfg.RawMessage `json:"app"`
	}
	var wire []grantWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	out := make(Grants, len(wire))
	for i, w := range wire {
		out[i] = Grant{Sources: w.Sources, Destinations: w.Destinations, App: w.App}
	}
	*g = out
	return nil
}

// UnmarshalJSON for NodeAttrs: target uses Aliases, attr is a plain string list.
func (n *NodeAttrs) UnmarshalJSON(b []byte) error {
	type attrWire struct {
		Target Aliases                  `json:"target"`
		Attr   []tailcfg.NodeCapability `json:"attr"`
	}
	var wire []attrWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	out := make(NodeAttrs, len(wire))
	for i, w := range wire {
		out[i] = NodeAttr{Target: w.Target, Attr: w.Attr}
	}
	*n = out
	return nil
}

// compileGrantRules converts Policy.Grants into tailcfg.FilterRule entries.
// Each grant becomes one FilterRule with SrcIPs resolved from grant.Sources
// and CapGrant[] whose Dsts resolve from grant.Destinations.
//
// A taildrive grant additionally produces a reverse FilterRule so that the
// destination side gets PeerCapabilityTaildriveSharer back toward sources.
func (pol *Policy) compileGrantRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil || len(pol.Grants) == 0 {
		return nil, nil
	}

	var rules []tailcfg.FilterRule
	for idx, g := range pol.Grants {
		srcSet, err := g.Sources.Resolve(pol, users, nodes)
		if err != nil {
			return nil, fmt.Errorf("grant[%d] src: %w", idx, err)
		}
		if srcSet == nil || len(srcSet.Prefixes()) == 0 {
			continue
		}
		srcIPs := ipSetToPrefixStringList(srcSet)

		capGrant, err := compileCapGrant(pol, users, nodes, g.Destinations, g.App)
		if err != nil {
			return nil, fmt.Errorf("grant[%d] dst: %w", idx, err)
		}
		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   srcIPs,
			CapGrant: capGrant,
		})

		// Taildrive: mirror the grant so the destination side sees the source
		// side as a sharer. This matches upstream Tailscale client expectations.
		if vals, ok := g.App[tailcfg.PeerCapabilityTaildrive]; ok && len(vals) > 0 {
			reverseApp := map[tailcfg.PeerCapability][]tailcfg.RawMessage{
				tailcfg.PeerCapabilityTaildriveSharer: nil,
			}
			reverseCapGrant, err := compileCapGrant(pol, users, nodes, g.Sources, reverseApp)
			if err != nil {
				return nil, fmt.Errorf("grant[%d] reverse taildrive-sharer dst: %w", idx, err)
			}
			// The reverse rule's source is the original grant's dst.
			destSet, err := g.Destinations.Resolve(pol, users, nodes)
			if err != nil {
				return nil, fmt.Errorf("grant[%d] reverse src: %w", idx, err)
			}
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   ipSetToPrefixStringList(destSet),
				CapGrant: reverseCapGrant,
			})
		}
	}

	return rules, nil
}

// compileCapGrant builds the tailcfg.CapGrant for a grant's destinations+app.
func compileCapGrant(
	pol *Policy,
	users types.Users,
	nodes views.Slice[types.NodeView],
	dsts Aliases,
	app map[tailcfg.PeerCapability][]tailcfg.RawMessage,
) ([]tailcfg.CapGrant, error) {
	dstSet, err := dsts.Resolve(pol, users, nodes)
	if err != nil {
		return nil, err
	}
	var dstPrefixes []netip.Prefix
	if dstSet != nil {
		dstPrefixes = dstSet.Prefixes()
	}

	// Copy app map so callers can't mutate our output via their input.
	capMap := make(tailcfg.PeerCapMap, len(app))
	for cap, vals := range app {
		if vals == nil {
			capMap[cap] = nil
			continue
		}
		capMap[cap] = append([]tailcfg.RawMessage(nil), vals...)
	}

	return []tailcfg.CapGrant{{
		Dsts:   dstPrefixes,
		CapMap: capMap,
	}}, nil
}

// nodeAttrsFor returns the set of NodeCapability strings that should be
// merged into the given node's tailcfg.Node.CapMap. A node matches a rule
// when it is contained in the union IPSet resolved from the rule's Target.
func (pol *Policy) nodeAttrsFor(
	users types.Users,
	nodes views.Slice[types.NodeView],
	node types.NodeView,
) []tailcfg.NodeCapability {
	if pol == nil || len(pol.NodeAttrs) == 0 {
		return nil
	}

	nodeIPs := node.IPs()
	if len(nodeIPs) == 0 {
		return nil
	}

	var out []tailcfg.NodeCapability
	seen := make(map[tailcfg.NodeCapability]struct{})
	for _, na := range pol.NodeAttrs {
		set, err := na.Target.Resolve(pol, users, nodes)
		if err != nil || set == nil {
			continue
		}
		matched := false
		for _, ip := range nodeIPs {
			if set.Contains(ip) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, cap := range na.Attr {
			if _, ok := seen[cap]; ok {
				continue
			}
			seen[cap] = struct{}{}
			out = append(out, cap)
		}
	}
	return out
}

// __END_CYLONIX_MOD__
