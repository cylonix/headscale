// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package state

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// ErrPresenceNotWireguardOnly is returned when presence is pushed for a node
// whose presence is owned by its own map-poll session.
var ErrPresenceNotWireguardOnly = errors.New(
	"presence updates are only accepted for wireguard-only nodes")

// presenceTransition is the pure decision behind SetWireguardOnlyPresence:
// given the node's current state and the requested presence, what actually
// changes. Kept separate so it can be unit-tested without a State.
type presenceTransition struct {
	OnlineChanged    bool
	WentOnline       bool
	EndpointsChanged bool
}

func (t presenceTransition) isNoop() bool {
	return !t.OnlineChanged && !t.EndpointsChanged
}

func decidePresence(
	n *types.Node,
	online *bool,
	endpoints []netip.AddrPort,
	hasEndpoints bool,
) presenceTransition {
	var t presenceTransition

	if online != nil {
		cur := n.IsOnline != nil && *n.IsOnline
		if cur != *online {
			t.OnlineChanged = true
			t.WentOnline = *online
		}
	}

	if hasEndpoints && !slices.Equal(n.Endpoints, endpoints) {
		t.EndpointsChanged = true
	}

	return t
}

// SetWireguardOnlyPresence applies manager-reported presence to a
// WireGuard-only node: the online flag and/or the endpoints.
//
// WireGuard-only nodes (cylonix gateways) never open a map-poll session, so
// nothing else ever sets their IsOnline; peers saw them as offline forever
// and endpoint changes had no path at all. This mirrors what Connect and
// Disconnect do for polling nodes, minus the session refcount, and it is
// idempotent: when nothing changed there is no database write and no change
// to broadcast, so the manager can call it on every heartbeat.
//
// LastSeen is derived from the transition (cleared when the node comes
// online, stamped when it goes offline) and persisted with an explicit column
// select so a nil value really becomes NULL.
func (s *State) SetWireguardOnlyPresence(
	id types.NodeID,
	online *bool,
	endpoints []netip.AddrPort,
	hasEndpoints bool,
) ([]change.Change, error) {
	cur, ok := s.nodeStore.GetNode(id)
	if !ok || !cur.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	if wg := cur.IsWireguardOnly(); !wg.Valid() || !wg.Get() {
		return nil, fmt.Errorf("%w: %d", ErrPresenceNotWireguardOnly, id)
	}

	var (
		tr  presenceTransition
		now = time.Now()
	)

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		tr = decidePresence(n, online, endpoints, hasEndpoints)

		if tr.OnlineChanged {
			n.IsOnline = ptr.To(tr.WentOnline)
			if tr.WentOnline {
				n.LastSeen = nil
			} else {
				n.LastSeen = ptr.To(now)
			}
		}

		if tr.EndpointsChanged {
			n.Endpoints = slices.Clone(endpoints)
		}
	})
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	if tr.isNoop() {
		return nil, nil
	}

	// Persist only the columns that moved. Select forces zero values through,
	// which is how a cleared LastSeen reaches the database as NULL.
	persist := &types.Node{ID: id}

	var cols []string

	if tr.OnlineChanged {
		cols = append(cols, "last_seen")
		if !tr.WentOnline {
			persist.LastSeen = ptr.To(now)
		}
	}

	if tr.EndpointsChanged {
		cols = append(cols, "endpoints")
		persist.Endpoints = slices.Clone(endpoints)
	}

	if err := s.db.DB.Model(&types.Node{ID: id}).Select(cols).Updates(persist).Error; err != nil {
		return nil, fmt.Errorf("persisting presence for node %d: %w", id, err)
	}

	var cs []change.Change

	if tr.OnlineChanged {
		if tr.WentOnline {
			routeChange := s.primaryRoutes.SetRoutes(id, node.AllApprovedRoutes()...)

			cs = append(cs, change.NodeOnlineFor(node))
			if routeChange {
				cs = append(cs, change.NodeAdded(id))
			}
		} else {
			routeChange := s.primaryRoutes.SetRoutes(id)

			cs = append(cs, change.NodeOfflineFor(node))
			if routeChange {
				cs = append(cs, change.PolicyChange())
			}
		}

		log.Info().
			Uint64("node.id", id.Uint64()).
			Str("node.name", node.Hostname()).
			Bool("online", tr.WentOnline).
			Msg("WireGuard-only node presence changed")
	}

	if tr.EndpointsChanged {
		cs = append(cs, change.EndpointOrDERPUpdate(id, &tailcfg.PeerChange{
			NodeID:    id.NodeID(),
			Endpoints: slices.Clone(endpoints),
		}))
	}

	return cs, nil
}

// SetNodeLastSeen sets (or, with nil, clears) a node's LastSeen in the store
// and the database. Admin use through the UpdateNode "last_seen" mask path;
// presence transitions derive LastSeen themselves.
func (s *State) SetNodeLastSeen(id types.NodeID, lastSeen *time.Time) error {
	if _, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.LastSeen = lastSeen
	}); !ok {
		return fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	err := s.db.DB.Model(&types.Node{ID: id}).
		Select("last_seen").
		Updates(&types.Node{ID: id, LastSeen: lastSeen}).Error
	if err != nil {
		return fmt.Errorf("persisting last_seen for node %d: %w", id, err)
	}

	return nil
}

// PutCreatedNode adds a node that has already been written to the database
// (cylonix CreateNode RPC) to the NodeStore, refreshes policy state, and
// registers its primary routes if it was created online. It returns the
// change to broadcast. Without this the mapper, which reads the store only,
// did not know the node existed until the next restart.
func (s *State) PutCreatedNode(node *types.Node) (types.NodeView, change.Change, error) {
	if node == nil || node.ID == 0 {
		return types.NodeView{}, change.Change{}, errors.New("PutCreatedNode: node without an ID")
	}

	nv := s.nodeStore.PutNode(*node)

	if node.IsOnline != nil && *node.IsOnline {
		s.primaryRoutes.SetRoutes(node.ID, nv.AllApprovedRoutes()...)
	}

	c, err := s.updatePolicyManagerNodesForTailnet(node.NetworkDomain)
	if err != nil {
		return nv, change.Change{}, fmt.Errorf("updating policy manager after node create: %w", err)
	}

	if c.IsEmpty() {
		c = change.NodeAdded(node.ID)
	}

	return nv, c, nil
}
