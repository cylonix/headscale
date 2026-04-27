// __BEGIN_CYLONIX_MOD__
// Namespace-scoped primary-route selection.
//
// Upstream's PrimaryRoutes is a single global struct that picks one primary
// node per prefix across the whole headscale state. Cylonix runs headscale as
// a multi-tenant control plane with a two-level hierarchy:
//
//   namespace  ->  network_domain  ->  user / node / route / ...
//
// A namespace is a tenant; a tenant can contain multiple network domains, and
// nodes isolated under different network domains must not fail over routes
// between each other even if they belong to the same namespace. The shard key
// is therefore the (namespace, network_domain) pair.
//
// Upstream v0.28 has no native multi-tenancy concept and never will (the
// upstream maintainer has declined to accept multi-tenancy contributions and
// positions headscale as a home-lab control plane). The cylonix multi-tenant
// layer is therefore maintained permanently in this package and its siblings.
//
// ScopedPrimaryRoutes wraps PrimaryRoutes per (namespace, network_domain).
// Callers are expected to resolve the scope for a given NodeID from the node
// store (types.Node.Namespace and types.Node.NetworkDomain) before invoking
// Set/Get/Remove.
//
// Concurrent callers are serialized through an RWMutex protecting the shard
// map; each shard (PrimaryRoutes) has its own internal lock.
//
// NOT YET WIRED INTO state.State. state.State still uses the single-shard
// routes.PrimaryRoutes (upstream v0.28 default). This file is scaffolding for
// a follow-up commit that will:
//   1. replace state.State.primaryRoutes with *ScopedPrimaryRoutes
//   2. add a types.Node.RouteScope() helper (returns namespace + network)
//   3. thread scope through the state.go call sites that touch primary-route
//      state
//
// Until that follow-up lands, cylonix runs with upstream's single-shard
// behavior — a latent correctness issue only triggered when two network
// domains advertise the same prefix on the same headscale instance. The old
// cylonix code enforced scope at the DB query level, which is no longer
// possible since routes moved in-memory in upstream v0.26.

package routes

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
)

// ScopeKey identifies a (namespace, network_domain) pair for primary-route
// isolation. The zero value represents the "default" shard, which is
// functionally equivalent to upstream's single-shard behavior.
type ScopeKey struct {
	Namespace     string
	NetworkDomain string
}

// String renders a ScopeKey for log messages as "<namespace>/<network>".
func (k ScopeKey) String() string {
	if k.Namespace == "" && k.NetworkDomain == "" {
		return "<default>"
	}
	return fmt.Sprintf("%s/%s", k.Namespace, k.NetworkDomain)
}

// ScopedPrimaryRoutes shards PrimaryRoutes by (namespace, network_domain).
// Routes from different scopes never participate in the same primary-route
// selection, so failover cannot cross network-domain boundaries.
type ScopedPrimaryRoutes struct {
	mu     sync.RWMutex
	shards map[ScopeKey]*PrimaryRoutes
}

// NewScoped returns an empty scope-aware primary-routes tracker.
func NewScoped() *ScopedPrimaryRoutes {
	return &ScopedPrimaryRoutes{
		shards: make(map[ScopeKey]*PrimaryRoutes),
	}
}

// shard returns (creating if necessary) the PrimaryRoutes shard for key.
func (s *ScopedPrimaryRoutes) shard(key ScopeKey) *PrimaryRoutes {
	s.mu.RLock()
	pr, ok := s.shards[key]
	s.mu.RUnlock()
	if ok {
		return pr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pr, ok = s.shards[key]; ok {
		return pr
	}
	pr = New()
	s.shards[key] = pr
	return pr
}

// SetRoutes records the advertised+approved prefixes for a node scoped to
// (namespace, networkDomain). Returns true if primary-route assignments
// changed in that shard. Passing zero prefixes removes the node from the
// shard.
func (s *ScopedPrimaryRoutes) SetRoutes(namespace, networkDomain string, node types.NodeID, prefixes ...netip.Prefix) bool {
	return s.shard(ScopeKey{Namespace: namespace, NetworkDomain: networkDomain}).
		SetRoutes(node, prefixes...)
}

// PrimaryRoutes returns the primary prefixes served by the given node in the
// shard identified by (namespace, networkDomain). Returns nil if the node
// has no primary routes or the shard is empty.
func (s *ScopedPrimaryRoutes) PrimaryRoutes(namespace, networkDomain string, id types.NodeID) []netip.Prefix {
	key := ScopeKey{Namespace: namespace, NetworkDomain: networkDomain}
	s.mu.RLock()
	pr, ok := s.shards[key]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return pr.PrimaryRoutes(id)
}

// Remove drops the shard for (namespace, networkDomain). Used when a network
// domain is torn down.
func (s *ScopedPrimaryRoutes) Remove(namespace, networkDomain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.shards, ScopeKey{Namespace: namespace, NetworkDomain: networkDomain})
}

// RemoveNamespace drops every shard that belongs to namespace. Used when a
// tenant (namespace) is torn down and its network_domains are collateral.
func (s *ScopedPrimaryRoutes) RemoveNamespace(namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.shards {
		if k.Namespace == namespace {
			delete(s.shards, k)
		}
	}
}

// Scopes returns a snapshot of currently tracked scope keys, sorted by
// namespace then network_domain, for deterministic debug output.
func (s *ScopedPrimaryRoutes) Scopes() []ScopeKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopeKey, 0, len(s.shards))
	for k := range s.shards {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].NetworkDomain < out[j].NetworkDomain
	})
	return out
}

// String renders all shards, useful for debug endpoints.
func (s *ScopedPrimaryRoutes) String() string {
	var b strings.Builder
	for _, k := range s.Scopes() {
		fmt.Fprintf(&b, "[%s]\n%s\n", k, s.shard(k).String())
	}
	return b.String()
}

// __END_CYLONIX_MOD__
