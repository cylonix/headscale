// __BEGIN_CYLONIX_ADD__
// Package state share_edges.go provides SQL helpers for resolving the
// "share neighbour" graph between cylonix tailnets (network_domain values).
//
// Two nodes participate in the same tailnet iff they share the same
// users.network value (which is mirrored on nodes.network_domain). Cylonix
// allows nodes from one tailnet to be explicitly visible to users in another
// tailnet via accepted share grants stored in the
// node_accepted_share_to_users_relation table. Pending offers
// (node_would_share_to_users_relation) do not affect visibility and are
// ignored here.
//
// These helpers are pure SQL — they do not mutate the NodeStore or
// PolicyManager — and are intended to be called wrapped in
// hsdb.Read(s.db.DB, ...) at call sites that orchestrate per-tailnet peer
// cache rebuilds (see state.go::rebuildTailnet and
// state.go::tailnetNeighbours).
package state

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// shareNeighbours returns the set of network_domain values reachable from
// `tailnet` via accepted share grants in either direction. The result does
// NOT include `tailnet` itself.
//
// Outbound shares: tailnet T's nodes are shared TO users whose users.network
// is some other tailnet T'.
//
// Inbound shares: nodes whose nodes.network_domain is some other tailnet T'
// have been shared TO users whose users.network is T.
//
// The union of these two directions is T's neighbour set — the tailnets
// whose policy or node mutations can affect T's per-tailnet peer cache and
// must therefore trigger an invalidation in T.
func shareNeighbours(tx *gorm.DB, tailnet string) ([]string, error) {
	if tailnet == "" {
		return nil, nil
	}

	const q = `
SELECT DISTINCT u.network AS network_domain
FROM   node_accepted_share_to_users_relation r
JOIN   nodes n ON r.node_id = n.id
JOIN   users u ON r.user_id = u.id
WHERE  n.network_domain = ?
   AND u.network IS NOT NULL
   AND u.network != ''
   AND u.network != ?
UNION
SELECT DISTINCT n.network_domain AS network_domain
FROM   node_accepted_share_to_users_relation r
JOIN   nodes n ON r.node_id = n.id
JOIN   users u ON r.user_id = u.id
WHERE  u.network = ?
   AND n.network_domain IS NOT NULL
   AND n.network_domain != ''
   AND n.network_domain != ?
`

	var out []string
	if err := tx.Raw(q, tailnet, tailnet, tailnet, tailnet).Scan(&out).Error; err != nil {
		return nil, err
	}

	return out, nil
}

// nodesForTailnetAndShares returns three slices:
//
//   - own:        node IDs whose nodes.network_domain == tailnet
//   - sharedIn:   node IDs from OTHER tailnets that have been shared TO
//     users whose users.network == tailnet
//   - sharedOut:  node IDs of own nodes that have been shared TO users in
//     OTHER tailnets
//
// Only accepted shares (node_accepted_share_to_users_relation) are
// considered. Pending offers are ignored. The three slices are pairwise
// disjoint with respect to "own" — sharedIn never includes nodes whose
// network_domain == tailnet, and sharedOut is a subset of own (it
// represents the cross-edge endpoints in this tailnet, not foreign nodes).
func nodesForTailnetAndShares(tx *gorm.DB, tailnet string) (own, sharedIn, sharedOut []types.NodeID, err error) {
	if tailnet == "" {
		return nil, nil, nil, nil
	}

	// own
	if err = tx.Raw(
		`SELECT id FROM nodes WHERE network_domain = ? AND deleted_at IS NULL`,
		tailnet,
	).Scan(&own).Error; err != nil {
		return nil, nil, nil, err
	}

	// sharedIn: nodes from OTHER tailnets shared TO users in this tailnet.
	if err = tx.Raw(`
SELECT DISTINCT n.id
FROM   node_accepted_share_to_users_relation r
JOIN   nodes n ON r.node_id = n.id
JOIN   users u ON r.user_id = u.id
WHERE  u.network = ?
   AND (n.network_domain IS NULL OR n.network_domain != ?)
   AND n.deleted_at IS NULL
`, tailnet, tailnet).Scan(&sharedIn).Error; err != nil {
		return nil, nil, nil, err
	}

	// sharedOut: this tailnet's own nodes that have been shared OUT to
	// users in other tailnets. These are a subset of `own` and are
	// reported separately so callers can know which of their own nodes
	// participate in cross-tailnet visibility.
	if err = tx.Raw(`
SELECT DISTINCT n.id
FROM   node_accepted_share_to_users_relation r
JOIN   nodes n ON r.node_id = n.id
JOIN   users u ON r.user_id = u.id
WHERE  n.network_domain = ?
   AND u.network IS NOT NULL
   AND u.network != ''
   AND u.network != ?
   AND n.deleted_at IS NULL
`, tailnet, tailnet).Scan(&sharedOut).Error; err != nil {
		return nil, nil, nil, err
	}

	return own, sharedIn, sharedOut, nil
}

// __END_CYLONIX_ADD__
