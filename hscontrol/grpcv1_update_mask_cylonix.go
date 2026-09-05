// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hscontrol

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
)

// updateNodePlan is the parsed update_mask of an UpdateNodeRequest. See the
// field comment in node.proto for the contract.
type updateNodePlan struct {
	// legacy is set when the request carries no mask: the admin subset is
	// applied exactly as before the mask existed.
	legacy bool
	// admin is set when the mask names an admin path, or when add/del
	// capabilities are present.
	admin bool

	online       *bool
	endpoints    []netip.AddrPort
	hasEndpoints bool
	routes       []netip.Prefix
	hasRoutes    bool
	lastSeen     *time.Time
	hasLastSeen  bool
}

var updateNodeAdminPaths = map[string]bool{
	"name":           true,
	"given_name":     true,
	"namespace":      true,
	"network_domain": true,
	"wireguard_only": true,
	"stable_id":      true,
	"cap_version":    true,
	"health":         true,
	"capabilities":   true,
}

func (p updateNodePlan) hasPresence() bool { return p.online != nil || p.hasEndpoints }

func (p updateNodePlan) applyAdmin() bool { return p.legacy || p.admin }

func parseUpdateNodePlan(req *v1.UpdateNodeRequest) (updateNodePlan, error) {
	var plan updateNodePlan

	paths := req.GetUpdateMask().GetPaths()
	if len(paths) == 0 {
		plan.legacy = true

		return plan, nil
	}

	upd := req.GetUpdate()

	for _, path := range paths {
		switch {
		case path == "online":
			if upd == nil {
				return plan, status.Error(codes.InvalidArgument,
					"update_mask names online but update is empty")
			}

			v := upd.GetOnline()
			plan.online = &v

		case path == "endpoints":
			eps, err := types.ParseProtoEndpoints(upd.GetEndpoints())
			if err != nil {
				return plan, status.Error(codes.InvalidArgument, err.Error())
			}

			plan.endpoints, plan.hasEndpoints = eps, true

		case path == "routes":
			routes, err := types.ApprovedRoutesFromProtoRouteSpecs(upd.GetRoutes())
			if err != nil {
				return plan, status.Error(codes.InvalidArgument, err.Error())
			}

			plan.routes, plan.hasRoutes = routes, true

		case path == "last_seen":
			plan.hasLastSeen = true

			if ts := upd.GetLastSeen(); ts.IsValid() {
				t := ts.AsTime()
				plan.lastSeen = &t
			}

		case updateNodeAdminPaths[path]:
			plan.admin = true

		default:
			return plan, status.Errorf(codes.InvalidArgument, "update_mask: unknown path %q", path)
		}
	}

	if len(req.GetAddCapabilities()) > 0 || len(req.GetDelCapabilities()) > 0 {
		plan.admin = true
	}

	return plan, nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}

	return cmp.Compare(a.Bits(), b.Bits())
}

// applyUpdateNodePresence applies the presence, routes and last_seen paths of
// plan through the state layer and returns the changes to broadcast. Every
// path is idempotent: nothing is written or announced when the requested
// value already holds.
func (api headscaleV1APIServer) applyUpdateNodePresence(
	id types.NodeID,
	plan updateNodePlan,
) ([]change.Change, error) {
	var cs []change.Change

	if plan.hasPresence() {
		got, err := api.h.state.SetWireguardOnlyPresence(id, plan.online, plan.endpoints, plan.hasEndpoints)
		if err != nil {
			log.Warn().Err(err).
				Uint64("node.id", id.Uint64()).
				Msg("UpdateNode: presence update rejected")

			switch {
			case errors.Is(err, state.ErrPresenceNotWireguardOnly):
				return nil, status.Error(codes.FailedPrecondition, err.Error())
			case errors.Is(err, state.ErrNodeNotInNodeStore):
				return nil, status.Error(codes.NotFound, err.Error())
			default:
				return nil, err
			}
		}

		cs = append(cs, got...)
	}

	if plan.hasRoutes {
		cur, ok := api.h.state.GetNodeByID(id)
		if !ok || !cur.Valid() {
			return nil, status.Errorf(codes.NotFound, "node %d not in NodeStore", id)
		}

		want := slices.Clone(plan.routes)
		slices.SortFunc(want, comparePrefix)

		have := slices.Clone(cur.ApprovedRoutes().AsSlice())
		slices.SortFunc(have, comparePrefix)

		// SetApprovedRoutes always ends in a PolicyChange (a response for
		// every connected node), so only call it for a real change.
		if !slices.Equal(have, want) {
			_, c, err := api.h.state.SetApprovedRoutes(id, plan.routes)
			if err != nil {
				return nil, err
			}

			cs = append(cs, c)
		}
	}

	if plan.hasLastSeen {
		if err := api.h.state.SetNodeLastSeen(id, plan.lastSeen); err != nil {
			return nil, err
		}

		if plan.lastSeen != nil {
			cs = append(cs, change.Change{
				Reason: "last seen",
				PeerPatches: []*tailcfg.PeerChange{{
					NodeID:   id.NodeID(),
					LastSeen: plan.lastSeen,
				}},
			})
		}
	}

	return cs, nil
}
