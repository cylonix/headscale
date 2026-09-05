// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"fmt"
	"net/netip"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"tailscale.com/types/ptr"
)

// RegisterMethodFromV1Enum is the inverse of Node.RegisterMethodToV1Enum.
func RegisterMethodFromV1Enum(m v1.RegisterMethod) string {
	switch m {
	case v1.RegisterMethod_REGISTER_METHOD_AUTH_KEY:
		return "authkey"
	case v1.RegisterMethod_REGISTER_METHOD_OIDC:
		return "oidc"
	case v1.RegisterMethod_REGISTER_METHOD_CLI:
		return "cli"
	default:
		return ""
	}
}

// ParseProtoNodeForCreate converts a full v1.Node into a *Node for the cylonix
// CreateNode RPC.
//
// ParseProtoNode is the partial admin-update subset and deliberately ignores
// identity and addressing. That is right for UpdateNode but wrong for
// creation: the pre-v0.28-merge converter honored keys, IPs, tags, register
// method, expiry and last_seen, and the "Merge upstream headscale v0.28.0"
// commit (fd41ed4c) replaced it with the subset, so nodes created through the
// RPC landed without keys, addresses or endpoints. This restores the full
// conversion and adds the cylonix presence fields (online, endpoints,
// routes). The user is resolved by the caller, which has the state.
func ParseProtoNodeForCreate(p *v1.Node) (*Node, error) {
	if p == nil {
		return nil, fmt.Errorf("ParseProtoNodeForCreate: nil proto Node")
	}

	n, err := ParseProtoNode(p, false)
	if err != nil {
		return nil, err
	}

	if s := p.GetMachineKey(); s != "" {
		if err := n.MachineKey.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("machine key: %w", err)
		}
	}

	if s := p.GetNodeKey(); s != "" {
		if err := n.NodeKey.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("node key: %w", err)
		}
	}

	if s := p.GetDiscoKey(); s != "" {
		if err := n.DiscoKey.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("disco key: %w", err)
		}
	}

	for _, a := range p.GetIpAddresses() {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("ip address %q: %w", a, err)
		}

		if ip.Is4() {
			n.IPv4 = ptr.To(ip)
		} else {
			n.IPv6 = ptr.To(ip)
		}
	}

	n.Endpoints, err = ParseProtoEndpoints(p.GetEndpoints())
	if err != nil {
		return nil, err
	}

	n.ApprovedRoutes, err = ApprovedRoutesFromProtoRouteSpecs(p.GetRoutes())
	if err != nil {
		return nil, err
	}

	n.Tags = p.GetTags()
	n.RegisterMethod = RegisterMethodFromV1Enum(p.GetRegisterMethod())

	if ts := p.GetExpiry(); ts.IsValid() {
		n.Expiry = ptr.To(ts.AsTime())
	}

	if ts := p.GetLastSeen(); ts.IsValid() {
		n.LastSeen = ptr.To(ts.AsTime())
	}

	n.IsOnline = ptr.To(p.GetOnline())

	return n, nil
}

// ParseProtoEndpoints parses the "ip:port" strings of a v1.Node.
func ParseProtoEndpoints(in []string) ([]netip.AddrPort, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make([]netip.AddrPort, 0, len(in))
	for _, s := range in {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", s, err)
		}

		out = append(out, ap)
	}

	return out, nil
}

// ApprovedRoutesFromProtoRouteSpecs returns the enabled prefixes of specs as
// the node's approved routes.
func ApprovedRoutesFromProtoRouteSpecs(specs []*v1.RouteSpec) ([]netip.Prefix, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	out := make([]netip.Prefix, 0, len(specs))
	for _, spec := range specs {
		if spec == nil || !spec.GetEnabled() {
			continue
		}

		pfx, err := netip.ParsePrefix(spec.GetPrefix())
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", spec.GetPrefix(), err)
		}

		out = append(out, pfx)
	}

	return out, nil
}
