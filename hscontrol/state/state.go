// Package state provides core state management for Headscale, coordinating
// between subsystems like database, IP allocation, policy management, and DERP routing.

package state

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	zcache "zgo.at/zcache/v2"
)

const (
	// registerCacheExpiration defines how long node registration entries remain in cache.
	registerCacheExpiration = time.Minute * 15

	// registerCacheCleanup defines the interval for cleaning up expired cache entries.
	registerCacheCleanup = time.Minute * 20

	// defaultNodeStoreBatchSize is the default number of write operations to batch
	// before rebuilding the in-memory node snapshot.
	defaultNodeStoreBatchSize = 100

	// defaultNodeStoreBatchTimeout is the default maximum time to wait before
	// processing a partial batch of node operations.
	defaultNodeStoreBatchTimeout = 500 * time.Millisecond
)

// ErrUnsupportedPolicyMode is returned for invalid policy modes. Valid modes are "file" and "db".
var ErrUnsupportedPolicyMode = errors.New("unsupported policy mode")

// ErrNodeNotFound is returned when a node cannot be found by its ID.
var ErrNodeNotFound = errors.New("node not found")

// ErrInvalidNodeView is returned when an invalid node view is provided.
var ErrInvalidNodeView = errors.New("invalid node view provided")

// ErrNodeNotInNodeStore is returned when a node no longer exists in the NodeStore.
var ErrNodeNotInNodeStore = errors.New("node no longer exists in NodeStore")

// ErrNodeNameNotUnique is returned when a node name is not unique.
var ErrNodeNameNotUnique = errors.New("node name is not unique")

// State manages Headscale's core state, coordinating between database, policy management,
// IP allocation, and DERP routing. All methods are thread-safe.
type State struct {
	// cfg holds the current Headscale configuration
	cfg *types.Config

	// nodeStore provides an in-memory cache for nodes.
	nodeStore *NodeStore

	// subsystem keeping state
	// db provides persistent storage and database operations
	db *hsdb.HSDatabase
	// ipAlloc manages IP address allocation for nodes
	ipAlloc *hsdb.IPAllocator
	// derpMap contains the current DERP relay configuration
	derpMap atomic.Pointer[tailcfg.DERPMap]
	// polMan handles policy evaluation and management
	polMan policy.PolicyManager
	// registrationCache caches node registration data to reduce database load
	registrationCache *zcache.Cache[types.RegistrationID, types.RegisterNode]
	// primaryRoutes tracks primary route assignments for nodes
	primaryRoutes *routes.PrimaryRoutes
}

// NewState creates and initializes a new State instance, setting up the database,
// IP allocator, DERP map, policy manager, and loading existing users and nodes.
func NewState(cfg *types.Config) (*State, error) {
	cacheExpiration := registerCacheExpiration
	if cfg.Tuning.RegisterCacheExpiration != 0 {
		cacheExpiration = cfg.Tuning.RegisterCacheExpiration
	}

	cacheCleanup := registerCacheCleanup
	if cfg.Tuning.RegisterCacheCleanup != 0 {
		cacheCleanup = cfg.Tuning.RegisterCacheCleanup
	}

	registrationCache := zcache.New[types.RegistrationID, types.RegisterNode](
		cacheExpiration,
		cacheCleanup,
	)

	registrationCache.OnEvicted(
		func(id types.RegistrationID, rn types.RegisterNode) {
			rn.SendAndClose(nil)
		},
	)

	db, err := hsdb.NewHeadscaleDatabase(
		cfg,
		registrationCache,
	)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	ipAlloc, err := hsdb.NewIPAllocator(db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, fmt.Errorf("init ip allocatior: %w", err)
	}

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
	}

	// On startup, all nodes should be marked as offline until they reconnect
	// This ensures we don't have stale online status from previous runs
	for _, node := range nodes {
		node.IsOnline = ptr.To(false)
	}

	users, err := db.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	pol, err := hsdb.PolicyBytes(db.DB, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	polMan, err := policy.NewPolicyManager(pol, users, nodes.ViewSlice())
	if err != nil {
		return nil, fmt.Errorf("init policy manager: %w", err)
	}

	// Apply defaults for NodeStore batch configuration if not set.
	// This ensures tests that create Config directly (without viper) still work.
	batchSize := cfg.Tuning.NodeStoreBatchSize
	if batchSize == 0 {
		batchSize = defaultNodeStoreBatchSize
	}

	batchTimeout := cfg.Tuning.NodeStoreBatchTimeout
	if batchTimeout == 0 {
		batchTimeout = defaultNodeStoreBatchTimeout
	}

	// PolicyManager.BuildPeerMap handles both global and per-node filter complexity.
	// This moves the complex peer relationship logic into the policy package where it belongs.
	nodeStore := NewNodeStore(
		nodes,
		func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
			return polMan.BuildPeerMap(views.SliceOf(nodes))
		},
		batchSize,
		batchTimeout,
	)
	nodeStore.Start()

	return &State{
		cfg: cfg,

		db:                db,
		ipAlloc:           ipAlloc,
		polMan:            polMan,
		registrationCache: registrationCache,
		primaryRoutes:     routes.New(),
		nodeStore:         nodeStore,
	}, nil
}

// Close gracefully shuts down the State instance and releases all resources.
func (s *State) Close() error {
	s.nodeStore.Stop()

	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	return nil
}

// SetDERPMap updates the DERP relay configuration.
func (s *State) SetDERPMap(dm *tailcfg.DERPMap) {
	s.derpMap.Store(dm)
}

// DERPMap returns the current DERP relay configuration for peer-to-peer connectivity.
func (s *State) DERPMap() tailcfg.DERPMapView {
	return s.derpMap.Load().View()
}

// ReloadPolicy reloads the access control policy and triggers auto-approval if changed.
// Returns true if the policy changed.
func (s *State) ReloadPolicy() ([]change.Change, error) {
	// __BEGIN_CYLONIX_MOD__
	// In multi-tenant mode there is no single global policy: each
	// (namespace, network) row is independent and lives in
	// PolicyManager.tailnetPolicies, not pm.matchers. Reload by
	// enumerating the latest row per (namespace, network) and
	// installing each. The global pm.matchers is left at whatever it
	// was constructed with at startup (empty → FilterAllowAll), which
	// is the correct fallback for tenants that haven't installed a
	// policy yet.
	policyChanged := false
	if s.cfg != nil && s.cfg.Policy.Mode == types.PolicyModeMulti {
		rows, err := hsdb.ListLatestPolicyPerTailnet(s.db.DB)
		if err != nil {
			return nil, fmt.Errorf("loading per-tailnet policies: %w", err)
		}
		for _, row := range rows {
			tailnet := row.Network
			if tailnet == "" {
				continue
			}
			ch, err := s.polMan.SetTailnetPolicy(tailnet, []byte(row.Data))
			if err != nil {
				log.Warn().
					Err(err).
					Str("namespace", row.Namespace).
					Str("network", tailnet).
					Msg("ReloadPolicy: per-tailnet compile failed; skipping")
				continue
			}
			policyChanged = policyChanged || ch
		}
	} else {
		pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
		if err != nil {
			return nil, fmt.Errorf("loading policy: %w", err)
		}

		policyChanged, err = s.polMan.SetPolicy(pol)
		if err != nil {
			return nil, fmt.Errorf("setting policy: %w", err)
		}
	}
	// __END_CYLONIX_MOD__

	// __BEGIN_CYLONIX_MOD__
	// Invalidate every per-tailnet peer cache. We don't know which
	// tailnet(s) the new policy affects (the policy file may contain
	// rules across tailnets) so we conservatively invalidate all known
	// tailnets. The next ListPeers per tailnet will lazily rebuild only
	// what's needed. The legacy global rebuild path is kept as a safety
	// net for the no-NodeHandler case (single-tenant deployments) where
	// the per-tailnet path is not in use.
	s.invalidateAllTailnetCaches()
	s.nodeStore.RebuildPeerMaps()
	// __END_CYLONIX_MOD__

	cs := []change.Change{change.PolicyChange()}

	// Always call autoApproveNodes during policy reload, regardless of whether
	// the policy content has changed. This ensures that routes are re-evaluated
	// when they might have been manually disabled but could now be auto-approved
	// with the current policy.
	rcs, err := s.autoApproveNodes()
	if err != nil {
		return nil, fmt.Errorf("auto approving nodes: %w", err)
	}

	// TODO(kradalby): These changes can probably be safely ignored.
	// If the PolicyChange is happening, that will lead to a full update
	// meaning that we do not need to send individual route changes.
	cs = append(cs, rcs...)

	if len(rcs) > 0 || policyChanged {
		log.Info().
			Bool("policy.changed", policyChanged).
			Int("route.changes", len(rcs)).
			Int("total.changes", len(cs)).
			Msg("Policy reload completed with changes")
	}

	return cs, nil
}

// CreateUser creates a new user and updates the policy manager.
// Returns the created user, change set, and any error.
func (s *State) CreateUser(user types.User) (*types.User, change.Change, error) {
	if err := s.db.DB.Save(&user).Error; err != nil {
		return nil, change.Change{}, fmt.Errorf("creating user: %w", err)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		// Log the error but don't fail the user creation
		return &user, change.Change{}, fmt.Errorf("failed to update policy manager after user creation: %w", err)
	}

	// Even if the policy manager doesn't detect a filter change, SSH policies
	// might now be resolvable when they weren't before. If there are existing
	// nodes, we should send a policy change to ensure they get updated SSH policies.
	// TODO(kradalby): detect this, or rebuild all SSH policies so we can determine
	// this upstream.
	if c.IsEmpty() {
		c = change.PolicyChange()
	}

	log.Info().Str("user.name", user.Name).Msg("User created")

	return &user, c, nil
}

// UpdateUser modifies an existing user using the provided update function within a transaction.
// Returns the updated user, change set, and any error.
func (s *State) UpdateUser(userID types.UserID, updateFn func(*types.User) error) (*types.User, change.Change, error) {
	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := hsdb.GetUserByID(tx, userID)
		if err != nil {
			return nil, err
		}

		if err := updateFn(user); err != nil {
			return nil, err
		}

		// Use Updates() to only update modified fields, preserving unchanged values.
		err = tx.Updates(user).Error
		if err != nil {
			return nil, fmt.Errorf("updating user: %w", err)
		}

		return user, nil
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return user, change.Change{}, fmt.Errorf("failed to update policy manager after user update: %w", err)
	}

	// TODO(kradalby): We might want to update nodestore with the user data

	return user, c, nil
}

// DeleteUser permanently removes a user and all associated data (nodes, API keys, etc).
// This operation is irreversible.
// It also updates the policy manager to ensure ACL policies referencing the deleted
// user are re-evaluated immediately, fixing issue #2967.
func (s *State) DeleteUser(userID types.UserID) (change.Change, error) {
	err := s.db.DestroyUser(userID)
	if err != nil {
		return change.Change{}, err
	}

	// Update policy manager with the new user list (without the deleted user)
	// This ensures that if the policy references the deleted user, it gets
	// re-evaluated immediately rather than when some other operation triggers it.
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy after user deletion: %w", err)
	}

	// If the policy manager doesn't detect changes, still return UserRemoved
	// to ensure peer lists are refreshed
	if c.IsEmpty() {
		c = change.UserRemoved()
	}

	return c, nil
}

// RenameUser changes a user's name. The new name must be unique.
func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, change.Change, error) {
	return s.UpdateUser(userID, func(user *types.User) error {
		user.Name = newName
		return nil
	})
}

// GetUserByID retrieves a user by ID.
func (s *State) GetUserByID(userID types.UserID) (*types.User, error) {
	return s.db.GetUserByID(userID)
}

// GetUserByName retrieves a user by name.
func (s *State) GetUserByName(name string) (*types.User, error) {
	return s.db.GetUserByName(name)
}

// GetUserByOIDCIdentifier retrieves a user by their OIDC identifier.
func (s *State) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return s.db.GetUserByOIDCIdentifier(id)
}

// ListUsersWithFilter retrieves users matching the specified filter criteria.
func (s *State) ListUsersWithFilter(filter *types.User) ([]types.User, error) {
	return s.db.ListUsers(filter)
}

// ListAllUsers retrieves all users in the system.
func (s *State) ListAllUsers() ([]types.User, error) {
	return s.db.ListUsers()
}

// persistNodeToDB saves the given node state to the database.
// This function must receive the exact node state to save to ensure consistency between
// NodeStore and the database. It verifies the node still exists in NodeStore to prevent
// race conditions where a node might be deleted between UpdateNode returning and
// persistNodeToDB being called.
func (s *State) persistNodeToDB(node types.NodeView) (types.NodeView, change.Change, error) {
	if !node.Valid() {
		return types.NodeView{}, change.Change{}, ErrInvalidNodeView
	}

	// Verify the node still exists in NodeStore before persisting to database.
	// Without this check, we could hit a race condition where UpdateNode returns a valid
	// node from a batch update, then the node gets deleted (e.g., ephemeral node logout),
	// and persistNodeToDB would incorrectly re-insert the deleted node into the database.
	_, exists := s.nodeStore.GetNode(node.ID())
	if !exists {
		log.Warn().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Bool("is_ephemeral", node.IsEphemeral()).
			Msg("Node no longer exists in NodeStore, skipping database persist to prevent race condition")

		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, node.ID())
	}

	nodePtr := node.AsStruct()

	// Use Omit to prevent overwriting certain fields during MapRequest updates:
	// - "expiry": should only be updated through explicit SetNodeExpiry calls or re-registration
	// - "AuthKeyID", "AuthKey": prevents GORM from persisting stale PreAuthKey references that
	//   may exist in NodeStore after a PreAuthKey has been deleted. The database handles setting
	//   auth_key_id to NULL via ON DELETE SET NULL. Without this, Updates() would fail with a
	//   foreign key constraint error when trying to reference a deleted PreAuthKey.
	// See also: https://github.com/juanfont/headscale/issues/2862
	err := s.db.DB.Omit("expiry", "AuthKeyID", "AuthKey").Updates(nodePtr).Error
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("saving node: %w", err)
	}

	// Check if policy manager needs updating
	// __CYLONIX_MOD__ scope cache invalidation to the node's tailnet only
	c, err := s.updatePolicyManagerNodesForTailnet(nodePtr.NetworkDomain)
	if err != nil {
		return nodePtr.View(), change.Change{}, fmt.Errorf("failed to update policy manager after node save: %w", err)
	}

	if c.IsEmpty() {
		c = change.NodeAdded(node.ID())
	}

	return node, c, nil
}

func (s *State) SaveNode(node types.NodeView) (types.NodeView, change.Change, error) {
	// Update NodeStore first
	nodePtr := node.AsStruct()

	resultNode := s.nodeStore.PutNode(*nodePtr)

	// Then save to database using the result from PutNode
	return s.persistNodeToDB(resultNode)
}

// DeleteNode permanently removes a node and cleans up associated resources.
// Returns whether policies changed and any error. This operation is irreversible.
func (s *State) DeleteNode(node types.NodeView) (change.Change, error) {
	s.nodeStore.DeleteNode(node.ID())

	err := s.db.DeleteNode(node.AsStruct())
	if err != nil {
		return change.Change{}, err
	}

	// __BEGIN_CYLONIX_MOD__ Free IPs back to the cylonix allocator when
	// configured, otherwise to the headscale-local pool. Upstream calls
	// s.ipAlloc.FreeIPs unconditionally.
	if s.cfg != nil && s.cfg.IPAllocator != nil {
		owner := node.AsStruct().User
		mk := node.AsStruct().MachineKey
		for _, ip := range node.IPs() {
			ip := ip
			if ferr := s.cfg.IPAllocator.FreeFor(&ip, owner, &mk); ferr != nil {
				log.Warn().
					Err(ferr).
					Str("ip", ip.String()).
					Uint64("node.id", node.ID().Uint64()).
					Msg("cylonix IPAllocator.FreeFor failed")
			}
		}
	} else {
		s.ipAlloc.FreeIPs(node.IPs())
	}
	// __END_CYLONIX_MOD__

	c := change.NodeRemoved(node.ID())

	// Check if policy manager needs updating after node deletion
	// __CYLONIX_MOD__ scope cache invalidation to the deleted node's tailnet
	policyChange, err := s.updatePolicyManagerNodesForTailnet(node.NetworkDomain())
	if err != nil {
		return change.Change{}, fmt.Errorf("failed to update policy manager after node deletion: %w", err)
	}

	if !policyChange.IsEmpty() {
		// Merge policy change with NodeRemoved to preserve PeersRemoved info
		// This ensures the batcher cleans up the deleted node from its state
		c = c.Merge(policyChange)
	}

	return c, nil
}

// Connect marks a node as connected and updates its primary routes in the state.
//
// __CYLONIX_MOD__ Connect acquires one live poll session and returns a
// session epoch alongside the changes (backport of the upstream v0.29
// ActiveSessions/SessionEpoch fix, upstream commit 759381ad). The caller
// must release the session with exactly one Disconnect call once the
// session ends (see poll.go); the node goes offline when its LAST live
// session is released. Without this, a stale session teardown whose ~10s
// reconnect grace expired just as the client reconnected would run
// Disconnect AFTER the new session's Connect, clobbering IsOnline and
// broadcasting NodeOffline — peers then saw the node offline until its
// next reconnect even though its poll stream was alive.
func (s *State) Connect(id types.NodeID) ([]change.Change, uint64) {
	// CRITICAL FIX: Update the online status in NodeStore BEFORE creating change notification
	// This ensures that when the NodeCameOnline change is distributed and processed by other nodes,
	// the NodeStore already reflects the correct online status for full map generation.
	// now := time.Now()
	var epoch uint64 // __CYLONIX_ADD__
	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		// __BEGIN_CYLONIX_ADD__
		n.SessionEpoch++
		epoch = n.SessionEpoch
		n.ActiveSessions++
		// __END_CYLONIX_ADD__
		n.IsOnline = ptr.To(true)
		// n.LastSeen = ptr.To(now)
	})
	if !ok {
		return nil, 0
	}

	c := []change.Change{change.NodeOnlineFor(node)}

	log.Info().Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Node connected")

	// Use the node's current routes for primary route update
	// AllApprovedRoutes() returns only the intersection of announced AND approved routes
	// We MUST use AllApprovedRoutes() to maintain the security model
	routeChange := s.primaryRoutes.SetRoutes(id, node.AllApprovedRoutes()...)

	if routeChange {
		c = append(c, change.NodeAdded(id))
	}

	return c, epoch
}

// Disconnect marks a node as disconnected and updates its primary routes in the state.
//
// __CYLONIX_MOD__ Disconnect releases one poll session previously acquired
// by Connect and marks the node offline only when that was its last live
// session (backport of the upstream v0.29 ActiveSessions fix). Sessions
// are counted rather than compared by epoch: overlapping sessions for one
// node — a rapid reconnect, or a cancelled map request whose handler ran
// late — release in any order without stranding the node. An
// epoch-equality gate here loses when a dead-on-arrival session's Connect
// steals the latest epoch and its cleanup skips the release: the surviving
// session's Disconnect would then be rejected as stale and the node stays
// online forever. The count check and the IsOnline write share a
// NodeStore.UpdateNode closure, making them atomic against concurrent
// connects. epoch identifies the session for logging only.
func (s *State) Disconnect(id types.NodeID, epoch uint64) ([]change.Change, error) {
	// __BEGIN_CYLONIX_MOD__
	var wentOffline bool

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		if n.ActiveSessions > 0 {
			n.ActiveSessions--
		}

		if n.ActiveSessions > 0 {
			return
		}

		wentOffline = true

		now := time.Now()
		n.LastSeen = ptr.To(now)
		// NodeStore is the source of truth for all node state including online status.
		n.IsOnline = ptr.To(false)
	})

	if !ok {
		return nil, fmt.Errorf("node not found: %d", id)
	}

	if !wentOffline {
		log.Debug().
			Uint64("node.id", id.Uint64()).
			Uint64("disconnect_epoch", epoch).
			Int("active_sessions", node.ActiveSessions()).
			Msg("session released, other sessions keep node online")

		return nil, nil
	}
	// __END_CYLONIX_MOD__

	log.Info().Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Node disconnected")

	// Special error handling for disconnect - we log errors but continue
	// because NodeStore is already updated and we need to notify peers
	_, c, err := s.persistNodeToDB(node)
	if err != nil {
		// Log error but don't fail the disconnection - NodeStore is already updated
		// and we need to send change notifications to peers
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Failed to update last seen in database")

		c = change.Change{}
	}

	// The node is disconnecting so make sure that none of the routes it
	// announced are served to any nodes.
	routeChange := s.primaryRoutes.SetRoutes(id)

	cs := []change.Change{change.NodeOfflineFor(node), c}

	// If we have a policy change or route change, return that as it's more comprehensive
	// Otherwise, return the NodeOffline change to ensure nodes are notified
	if c.IsFull() || routeChange {
		cs = append(cs, change.PolicyChange())
	}

	return cs, nil
}

// GetNodeByID retrieves a node by ID.
// GetNodeByID retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByID(nodeID types.NodeID) (types.NodeView, bool) {
	return s.nodeStore.GetNode(nodeID)
}

// GetNodeByNodeKey retrieves a node by its Tailscale public key.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	return s.nodeStore.GetNodeByNodeKey(nodeKey)
}

// __BEGIN_CYLONIX_ADD__
// UpdateNode applies a mutation to a node in the NodeStore. Used by the
// auth-path key rotation so the NoisePollNetMap lookup by the new node key
// resolves immediately (db.NodeSetNodeKey only updates the persisted row).
func (s *State) UpdateNode(nodeID types.NodeID, fn func(*types.Node)) (types.NodeView, bool) {
	return s.nodeStore.UpdateNode(nodeID, fn)
}

// __END_CYLONIX_ADD__

// GetNodeByMachineKey retrieves a node by its machine key and user ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByMachineKey(machineKey key.MachinePublic, userID types.UserID) (types.NodeView, bool) {
	return s.nodeStore.GetNodeByMachineKey(machineKey, userID)
}

// ListNodes retrieves specific nodes by ID, or all nodes if no IDs provided.
func (s *State) ListNodes(nodeIDs ...types.NodeID) views.Slice[types.NodeView] {
	if len(nodeIDs) == 0 {
		return s.nodeStore.ListNodes()
	}

	// Filter nodes by the requested IDs
	allNodes := s.nodeStore.ListNodes()

	nodeIDSet := make(map[types.NodeID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView

	for _, node := range allNodes.All() {
		if _, exists := nodeIDSet[node.ID()]; exists {
			filteredNodes = append(filteredNodes, node)
		}
	}

	return views.SliceOf(filteredNodes)
}

// ListNodesByUser retrieves all nodes belonging to a specific user.
func (s *State) ListNodesByUser(userID types.UserID) views.Slice[types.NodeView] {
	return s.nodeStore.ListNodesByUser(userID)
}

// ListOnlineNodeIDs returns the IDs of all nodes currently connected, per the
// NodeStore — the source of truth for online status in v0.28 (Connect sets
// IsOnline=true; LastSeen is only written on Disconnect). Callers (e.g. the
// cylonix manager's online counts) should use this rather than LastSeen
// recency, which no longer reflects an active connection. __CYLONIX_MOD__
func (s *State) ListOnlineNodeIDs() []types.NodeID {
	nodes := s.nodeStore.ListNodes()
	ids := make([]types.NodeID, 0, nodes.Len())
	for _, nv := range nodes.All() {
		if o := nv.IsOnline(); o.Valid() && o.Get() {
			ids = append(ids, nv.ID())
		}
	}
	return ids
}

// ListPeers retrieves nodes that can communicate with the specified node based on policy.
// __BEGIN_CYLONIX_MOD__
// When a NodeHandler is configured, the caller-visible peer set is the
// intersection of two sources:
//
//   - The policy-derived peer map (cached in nodeStore.peersByNode, built
//     once per snapshot rebuild via polMan.BuildPeerMap). This represents
//     the upstream tailscale ACL/connectivity filter.
//
//   - The cylonix-derived peer list (NodeHandler.Peers(node), one DB call
//     per requesting node). This represents multi-tenancy (namespace +
//     network_domain) plus cylonix-side policy and label-sharing.
//
// Pre-merge cylonix relied on NodeHandler.Peers alone because upstream
// policy didn't constrain peer visibility (only connection permissions).
// In v0.28 polMan.BuildPeerMap CAN limit visibility, so we intersect.
// See memory: project_premerge_peer_and_authscope.md.
//
// The intersection is computed lazily here, on the read path, rather than
// in the peersFunc passed to NewNodeStore — the latter would call
// NodeHandler.Peers N times per snapshot rebuild instead of once per
// MapResponse poll.
func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) views.Slice[types.NodeView] {
	// Determine the requesting node and its tailnet. We need the tailnet
	// to consult the per-tailnet peer cache; if we can't resolve a node
	// we fall back to the flattened mirror.
	requesting, requestingOk := s.nodeStore.GetNode(nodeID)

	var (
		policyPeers    views.Slice[types.NodeView]
		gotPolicyPeers bool
	)
	if requestingOk && requesting.Valid() {
		tailnet := requesting.NetworkDomain()
		if tailnet != "" {
			// Lazy rebuild: if the per-tailnet cache is stale, fix it
			// before reading. rebuildTailnet is idempotent and does its
			// own DB lookup for the share-edge graph.
			if !s.nodeStore.IsTailnetCacheValid(tailnet) {
				if err := s.rebuildTailnet(tailnet); err != nil {
					log.Warn().
						Err(err).
						Str("tailnet", tailnet).
						Uint64("node.id", nodeID.Uint64()).
						Msg("rebuildTailnet failed; falling back to flattened peer mirror")
				}
			}
			if peers, ok := s.nodeStore.PeersForTailnet(tailnet, nodeID); ok {
				policyPeers = peers
				gotPolicyPeers = true
			}
		}
	}
	if !gotPolicyPeers {
		// Fallback to the flattened mirror — covers single-tenant
		// deployments where NetworkDomain is empty and the per-tailnet
		// cache is never built, plus error paths above.
		policyPeers = s.nodeStore.ListPeers(nodeID)
	}

	if len(peerIDs) > 0 {
		policyPeers = filterPeersByID(s.nodeStore, peerIDs)
	}

	if s.cfg == nil || s.cfg.NodeHandler == nil {
		return policyPeers
	}

	// Apply the cylonix multi-tenancy / policy / sharing filter.
	if !requestingOk || !requesting.Valid() {
		return policyPeers
	}
	_, cylonixIDs, _, err := s.cfg.NodeHandler.Peers(requesting.AsStruct())
	if err != nil {
		log.Warn().
			Err(err).
			Uint64("node.id", nodeID.Uint64()).
			Msg("NodeHandler.Peers failed; falling back to policy-only peer set")
		return policyPeers
	}

	allow := make(map[types.NodeID]struct{}, len(cylonixIDs))
	for _, id := range cylonixIDs {
		allow[id] = struct{}{}
	}
	out := make([]types.NodeView, 0, policyPeers.Len())
	for _, p := range policyPeers.All() {
		if _, ok := allow[p.ID()]; ok {
			out = append(out, p)
		}
	}
	return views.SliceOf(out)
}

// filterPeersByID returns the subset of nodes from the store whose IDs are
// in peerIDs. Extracted from the previous inlined ListPeers code path so
// the new intersection logic above stays focused.
func filterPeersByID(ns *NodeStore, peerIDs []types.NodeID) views.Slice[types.NodeView] {
	allNodes := ns.ListNodes()
	wanted := make(map[types.NodeID]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		wanted[id] = struct{}{}
	}
	out := make([]types.NodeView, 0, len(peerIDs))
	for _, node := range allNodes.All() {
		if _, ok := wanted[node.ID()]; ok {
			out = append(out, node)
		}
	}
	return views.SliceOf(out)
}

// NodeStore returns the underlying NodeStore. Exposed for callers in
// other packages that need to invalidate per-tailnet caches in response
// to share-grant mutations (e.g. grpcv1.UpdateNodeShareToUser).
func (s *State) NodeStore() *NodeStore {
	return s.nodeStore
}

// rebuildTailnet recomputes the per-tailnet peer cache for `tailnet` and
// pushes the result into the NodeStore. This is the heart of the
// per-tailnet refresh path:
//
//  1. Resolve the share-edge graph from the DB
//     (nodesForTailnetAndShares).
//  2. Look up the matching NodeViews from the NodeStore.
//  3. Call polMan.BuildPeerMapForTailnet over the union.
//  4. Push the result via nodeStore.RebuildTailnet.
//
// Called lazily from ListPeers when IsTailnetCacheValid(tailnet) is
// false. Safe to call concurrently — the NodeStore writeQueue serialises
// the final push.
func (s *State) rebuildTailnet(tailnet string) error {
	if tailnet == "" {
		return nil
	}

	type triple struct {
		own, sharedIn, sharedOut []types.NodeID
	}
	t, err := hsdb.Read(s.db.DB, func(rx *gorm.DB) (triple, error) {
		own, in, out, err := nodesForTailnetAndShares(rx, tailnet)
		if err != nil {
			return triple{}, err
		}
		return triple{own: own, sharedIn: in, sharedOut: out}, nil
	})
	if err != nil {
		return fmt.Errorf("loading share graph for tailnet %q: %w", tailnet, err)
	}

	// Resolve NodeIDs to NodeViews via the NodeStore. Missing nodes
	// (e.g. raced against a delete) are silently skipped.
	resolve := func(ids []types.NodeID) []types.NodeView {
		out := make([]types.NodeView, 0, len(ids))
		for _, id := range ids {
			if v, ok := s.nodeStore.GetNode(id); ok && v.Valid() {
				out = append(out, v)
			}
		}
		return out
	}

	ownNodes := views.SliceOf(resolve(t.own))
	sharedInNodes := views.SliceOf(resolve(t.sharedIn))
	sharedOutNodes := views.SliceOf(resolve(t.sharedOut))

	peerMap := s.polMan.BuildPeerMapForTailnet(tailnet, ownNodes, sharedInNodes, sharedOutNodes)
	if peerMap == nil {
		peerMap = make(map[types.NodeID][]types.NodeView)
	}

	s.nodeStore.RebuildTailnet(tailnet, ownNodes, sharedInNodes, sharedOutNodes, peerMap)
	return nil
}

// invalidateTailnetCascade marks the given tailnet's peer cache as stale
// AND propagates the invalidation to its share-edge neighbours. This is
// the standard "cylonix-side mutation" entry point used by SetPolicy and
// updatePolicyManagerNodes — both are scoped to a single tailnet but
// affect any neighbour with cross-tailnet shares to/from it.
func (s *State) invalidateTailnetCascade(tailnet string) {
	if tailnet == "" {
		return
	}

	s.nodeStore.InvalidatePeersForTailnet(tailnet)

	neighbours, err := hsdb.Read(s.db.DB, func(rx *gorm.DB) ([]string, error) {
		return shareNeighbours(rx, tailnet)
	})
	if err != nil {
		log.Warn().
			Err(err).
			Str("tailnet", tailnet).
			Msg("share-neighbour lookup failed during invalidation; only the source tailnet was invalidated")
		return
	}
	for _, n := range neighbours {
		if n != "" && n != tailnet {
			s.nodeStore.InvalidatePeersForTailnet(n)
		}
	}
}

// invalidateAllTailnetCaches walks every tailnet currently present in the
// NodeStore (by inspecting node NetworkDomain values) and marks each
// cache stale. Used by ReloadPolicy where the new policy may affect any
// tailnet, and we don't have a per-tailnet diff.
func (s *State) invalidateAllTailnetCaches() {
	seen := make(map[string]struct{})
	for _, n := range s.nodeStore.ListNodes().All() {
		if !n.Valid() {
			continue
		}
		t := n.NetworkDomain()
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		s.nodeStore.InvalidatePeersForTailnet(t)
	}
}

// __END_CYLONIX_MOD__

// ListEphemeralNodes retrieves all ephemeral (temporary) nodes in the system.
func (s *State) ListEphemeralNodes() views.Slice[types.NodeView] {
	allNodes := s.nodeStore.ListNodes()

	var ephemeralNodes []types.NodeView

	for _, node := range allNodes.All() {
		// Check if node is ephemeral by checking its AuthKey
		if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
			ephemeralNodes = append(ephemeralNodes, node)
		}
	}

	return views.SliceOf(ephemeralNodes)
}

// SetNodeExpiry updates the expiration time for a node.
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry time.Time) (types.NodeView, change.Change, error) {
	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change. If the database update fails, the NodeStore change will
	// remain, but since we return an error, no change notification will be sent to the
	// batcher, preventing inconsistent state propagation.
	expiryPtr := expiry
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Expiry = &expiryPtr
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	return s.persistNodeToDB(n)
}

// SetNodeTags assigns tags to a node, making it a "tagged node".
// Once a node is tagged, it cannot be un-tagged (only tags can be changed).
// The UserID is preserved as "created by" information.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (types.NodeView, change.Change, error) {
	// CANNOT REMOVE ALL TAGS
	if len(tags) == 0 {
		return types.NodeView{}, change.Change{}, types.ErrCannotRemoveAllTags
	}

	// Get node for validation
	existingNode, exists := s.nodeStore.GetNode(nodeID)
	if !exists {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotFound, nodeID)
	}

	// Validate tags: must have correct format and exist in policy
	validatedTags := make([]string, 0, len(tags))
	invalidTags := make([]string, 0)

	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || !s.polMan.TagExists(tag) {
			invalidTags = append(invalidTags, tag)

			continue
		}

		validatedTags = append(validatedTags, tag)
	}

	if len(invalidTags) > 0 {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, invalidTags)
	}

	slices.Sort(validatedTags)
	validatedTags = slices.Compact(validatedTags)

	// Log the operation
	logTagOperation(existingNode, validatedTags)

	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Tags = validatedTags
		// UserID is preserved as "created by" - do NOT set to nil
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	nodeView, c, err := s.persistNodeToDB(n)
	if err != nil {
		return nodeView, c, err
	}

	// Set OriginNode so the mapper knows to include self info for this node.
	// When tags change, persistNodeToDB returns PolicyChange which doesn't set OriginNode,
	// so the mapper's self-update check fails and the node never sees its new tags.
	// Setting OriginNode ensures the node gets a self-update with the new tags.
	c.OriginNode = nodeID

	return nodeView, c, nil
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, change.Change, error) {
	// TODO(kradalby): In principle we should call the AutoApprove logic here
	// because even if the CLI removes an auto-approved route, it will be added
	// back automatically.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	// Persist the node changes to the database
	nodeView, c, err := s.persistNodeToDB(n)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// Update primary routes table based on SubnetRoutes (intersection of announced and approved).
	// The primary routes table is what the mapper uses to generate network maps, so updating it
	// here ensures that route changes are distributed to peers.
	routeChange := s.primaryRoutes.SetRoutes(nodeID, nodeView.AllApprovedRoutes()...)

	// If routes changed or the changeset isn't already a full update, trigger a policy change
	// to ensure all nodes get updated network maps
	if routeChange || !c.IsFull() {
		c = change.PolicyChange()
	}

	return nodeView, c, nil
}

// RenameNode changes the display name of a node.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, change.Change, error) {
	err := util.ValidateHostname(newName)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("renaming node: %w", err)
	}

	// Check name uniqueness against NodeStore
	allNodes := s.nodeStore.ListNodes()
	for i := 0; i < allNodes.Len(); i++ {
		node := allNodes.At(i)
		if node.ID() != nodeID && node.AsStruct().GivenName == newName {
			return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %s", ErrNodeNameNotUnique, newName)
		}
	}

	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.GivenName = newName
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	return s.persistNodeToDB(n)
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them.
func (s *State) BackfillNodeIPs() ([]string, error) {
	changes, err := s.db.BackfillNodeIPs(s.ipAlloc)
	if err != nil {
		return nil, err
	}

	// Refresh NodeStore after IP changes to ensure consistency
	if len(changes) > 0 {
		nodes, err := s.db.ListNodes()
		if err != nil {
			return changes, fmt.Errorf("failed to refresh NodeStore after IP backfill: %w", err)
		}

		for _, node := range nodes {
			// Preserve online status and NetInfo when refreshing from database
			existingNode, exists := s.nodeStore.GetNode(node.ID)
			if exists && existingNode.Valid() {
				node.IsOnline = ptr.To(existingNode.IsOnline().Get())

				// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
				// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

				// Preserve NetInfo from existing node to prevent loss during backfill
				netInfo := netInfoFromMapRequest(node.ID, existingNode.Hostinfo().AsStruct(), node.Hostinfo)
				node.Hostinfo = existingNode.Hostinfo().AsStruct()
				node.Hostinfo.NetInfo = netInfo
			}
			// TODO(kradalby): This should just update the IP addresses, nothing else in the node store.
			// We should avoid PutNode here.
			_ = s.nodeStore.PutNode(*node)
		}
	}

	return changes, nil
}

// ExpireExpiredNodes finds and processes expired nodes since the last check.
// Returns next check time, state update with expired nodes, and whether any were found.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, []change.Change, bool) {
	// Why capture start time: We need to ensure we don't miss nodes that expire
	// while this function is running by using a consistent timestamp for the next check
	started := time.Now()

	var updates []change.Change

	for _, node := range s.nodeStore.ListNodes().All() {
		if !node.Valid() {
			continue
		}

		// Why check After(lastCheck): We only want to notify about nodes that
		// expired since the last check to avoid duplicate notifications
		if node.IsExpired() && node.Expiry().Valid() && node.Expiry().Get().After(lastCheck) {
			updates = append(updates, change.KeyExpiryFor(node.ID(), node.Expiry().Get()))
		}
	}

	if len(updates) > 0 {
		return started, updates, true
	}

	return started, nil, false
}

// SSHPolicy returns the SSH access policy for a node.
func (s *State) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	return s.polMan.SSHPolicy(node)
}

// Filter returns the current network filter rules and matches.
func (s *State) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	return s.polMan.Filter()
}

// FilterForNode returns filter rules for a specific node, handling autogroup:self per-node.
func (s *State) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	return s.polMan.FilterForNode(node)
}

// MatchersForNode returns matchers for peer relationship determination (unreduced).
func (s *State) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	return s.polMan.MatchersForNode(node)
}

// NodeCanHaveTag checks if a node is allowed to have a specific tag.
func (s *State) NodeCanHaveTag(node types.NodeView, tag string) bool {
	return s.polMan.NodeCanHaveTag(node, tag)
}

// SetPolicy updates the policy configuration.
func (s *State) SetPolicy(pol []byte) (bool, error) {
	// __BEGIN_CYLONIX_MOD__
	changed, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return changed, err
	}
	if changed {
		// We don't have a per-tailnet diff for raw policy bytes here
		// (the policy file may span tailnets), so invalidate every
		// tailnet's peer cache. ReloadPolicy follows the same pattern.
		s.invalidateAllTailnetCaches()
	}
	return changed, nil
	// __END_CYLONIX_MOD__
}

// __BEGIN_CYLONIX_ADD__
// PolicyManager returns the underlying policy.PolicyManager. Exposed
// so that gRPC handlers can use the per-tailnet policy operations
// (validate, set, clear) without going through the State layer for
// each, while still letting State own the lock-acquisition + cache
// invalidation policy where it matters.
func (s *State) PolicyManager() policy.PolicyManager {
	return s.polMan
}

// SetPolicyForTailnet installs a per-tailnet policy keyed by the given
// network_domain. Cylonix's `policies` table is keyed by (namespace,
// network); the State layer collapses to network_domain (== tailnet)
// because that's the cache key used by the NodeStore peer cache and
// because in cylonix's deploy a (namespace, network) pair maps 1:1 to
// a tailnet.
//
// On a real change, only the affected tailnet's cascade is invalidated
// — neighbour tailnets sharing nodes with this one are also flushed
// because their peer maps include nodes whose ACL visibility just
// changed.
//
// If pol is empty/nil, any existing per-tailnet policy is cleared and
// the tailnet falls back to the global policy. The cascade is still
// invalidated so the next ListPeers rebuilds with the global rules.
//
// Returns true if the in-memory matchers actually changed.
func (s *State) SetPolicyForTailnet(tailnet string, pol []byte) (bool, error) {
	if tailnet == "" {
		return false, fmt.Errorf("SetPolicyForTailnet: empty tailnet identifier")
	}

	var (
		changed bool
		err     error
	)
	if len(pol) == 0 {
		changed = s.polMan.ClearTailnetPolicy(tailnet)
	} else {
		changed, err = s.polMan.SetTailnetPolicy(tailnet, pol)
	}
	if err != nil {
		return false, err
	}

	if changed {
		s.invalidateTailnetCascade(tailnet)
	}
	return changed, nil
}

// __END_CYLONIX_ADD__

// AutoApproveRoutes checks if a node's routes should be auto-approved.
// AutoApproveRoutes checks if any routes should be auto-approved for a node and updates them.
func (s *State) AutoApproveRoutes(nv types.NodeView) (change.Change, error) {
	approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
	if changed {
		log.Debug().
			Uint64("node.id", nv.ID().Uint64()).
			Str("node.name", nv.Hostname()).
			Strs("routes.announced", util.PrefixesToString(nv.AnnouncedRoutes())).
			Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs("routes.approved.new", util.PrefixesToString(approved)).
			Msg("Single node auto-approval detected route changes")

		// Persist the auto-approved routes to database and NodeStore via SetApprovedRoutes
		// This ensures consistency between database and NodeStore
		_, c, err := s.SetApprovedRoutes(nv.ID(), approved)
		if err != nil {
			log.Error().
				Uint64("node.id", nv.ID().Uint64()).
				Str("node.name", nv.Hostname()).
				Err(err).
				Msg("Failed to persist auto-approved routes")

			return change.Change{}, err
		}

		log.Info().Uint64("node.id", nv.ID().Uint64()).Str("node.name", nv.Hostname()).Strs("routes.approved", util.PrefixesToString(approved)).Msg("Routes approved")

		return c, nil
	}

	return change.Change{}, nil
}

// GetPolicy retrieves the current policy from the database.
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy(nil, nil) // __CYLONIX_MOD__ unscoped lookup
}

// __BEGIN_CYLONIX_ADD__

// GetPolicyForNode retrieves the policy row scoped to a node's cylonix
// namespace and network domain. Used to overlay per-tenant policy settings
// (e.g. the derpMap section) onto map responses.
func (s *State) GetPolicyForNode(namespace, network string) (*types.Policy, error) {
	return s.db.GetPolicy(&namespace, &network)
}

// __END_CYLONIX_ADD__

// SetPolicyInDB stores policy data in the database.
func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data, "", "") // __CYLONIX_MOD__ no namespace/network scoping
}

// SetNodeRoutes sets the primary routes for a node.
func (s *State) SetNodeRoutes(nodeID types.NodeID, routes ...netip.Prefix) change.Change {
	if s.primaryRoutes.SetRoutes(nodeID, routes...) {
		// Route changes affect packet filters for all nodes, so trigger a policy change
		// to ensure filters are regenerated across the entire network
		return change.PolicyChange()
	}

	return change.Change{}
}

// GetNodePrimaryRoutes returns the primary routes for a node.
func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.primaryRoutes.PrimaryRoutes(nodeID)
}

// PrimaryRoutesString returns a string representation of all primary routes.
func (s *State) PrimaryRoutesString() string {
	return s.primaryRoutes.String()
}

// ValidateAPIKey checks if an API key is valid and active.
func (s *State) ValidateAPIKey(keyStr string) (bool, error) {
	return s.db.ValidateAPIKey(keyStr)
}

// CreateAPIKey generates a new API key with optional expiration.
func (s *State) CreateAPIKey(expiration *time.Time) (string, *types.APIKey, error) {
	return s.db.CreateAPIKey(expiration, "", "", "", "", "") // __CYLONIX_MOD__ no tenant scoping
}

// GetAPIKey retrieves an API key by its prefix.
// Accepts both display format (hskey-api-{12chars}-***) and database format ({12chars}).
func (s *State) GetAPIKey(displayPrefix string) (*types.APIKey, error) {
	// Parse the display prefix to extract the database prefix
	prefix, err := hsdb.ParseAPIKeyPrefix(displayPrefix)
	if err != nil {
		return nil, err
	}

	return s.db.GetAPIKey(prefix)
}

// GetAPIKeyByID retrieves an API key by its database ID.
func (s *State) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	return s.db.GetAPIKeyByID(id)
}

// ExpireAPIKey marks an API key as expired.
func (s *State) ExpireAPIKey(key *types.APIKey) error {
	return s.db.ExpireAPIKey(key)
}

// ListAPIKeys returns all API keys in the system.
func (s *State) ListAPIKeys() ([]types.APIKey, error) {
	return s.db.ListAPIKeys()
}

// DestroyAPIKey permanently removes an API key.
func (s *State) DestroyAPIKey(key types.APIKey) error {
	return s.db.DestroyAPIKey(key)
}

// CreatePreAuthKey generates a new pre-authentication key for a user.
// The userID parameter is now optional (can be nil) for system-created tagged keys.
func (s *State) CreatePreAuthKey(userID *types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKeyNew, error) {
	return s.db.CreatePreAuthKey(userID, reusable, ephemeral, expiration, aclTags)
}

// __BEGIN_CYLONIX_ADD__
// CreatePreAuthKeyExt generates a new pre-authentication key with cylonix
// tenant-scoping fields (namespace / ipv4 / ipv6 / description). Used by the
// gRPC handler when the request carries those fields; otherwise the unscoped
// CreatePreAuthKey path is used.
func (s *State) CreatePreAuthKeyExt(userID *types.UserID, reusable, ephemeral bool, expiration *time.Time, aclTags []string, namespace, ipv4, ipv6, description string) (*types.PreAuthKeyNew, error) {
	return s.db.CreatePreAuthKeyExt(userID, reusable, ephemeral, expiration, aclTags, hsdb.CreatePreAuthKeyExtParams{
		Namespace:   namespace,
		IPv4:        ipv4,
		IPv6:        ipv6,
		Description: description,
	})
}

// __END_CYLONIX_ADD__

// Test helpers for the state layer

// CreateUserForTest creates a test user. This is a convenience wrapper around the database layer.
func (s *State) CreateUserForTest(name ...string) *types.User {
	return s.db.CreateUserForTest(name...)
}

// CreateNodeForTest creates a test node. This is a convenience wrapper around the database layer.
func (s *State) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateNodeForTest(user, hostname...)
}

// CreateRegisteredNodeForTest creates a test node with allocated IPs. This is a convenience wrapper around the database layer.
func (s *State) CreateRegisteredNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateRegisteredNodeForTest(user, hostname...)
}

// CreateNodesForTest creates multiple test nodes. This is a convenience wrapper around the database layer.
func (s *State) CreateNodesForTest(user *types.User, count int, namePrefix ...string) []*types.Node {
	return s.db.CreateNodesForTest(user, count, namePrefix...)
}

// CreateUsersForTest creates multiple test users. This is a convenience wrapper around the database layer.
func (s *State) CreateUsersForTest(count int, namePrefix ...string) []*types.User {
	return s.db.CreateUsersForTest(count, namePrefix...)
}

// DB returns the underlying database for testing purposes.
func (s *State) DB() *hsdb.HSDatabase {
	return s.db
}

// GetPreAuthKey retrieves a pre-authentication key by ID.
func (s *State) GetPreAuthKey(id string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(id)
}

// ListPreAuthKeys returns all pre-authentication keys for a user.
func (s *State) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys()
}

// ExpirePreAuthKey marks a pre-authentication key as expired.
func (s *State) ExpirePreAuthKey(id uint64) error {
	return s.db.ExpirePreAuthKey(id)
}

// DeletePreAuthKey permanently deletes a pre-authentication key.
func (s *State) DeletePreAuthKey(id uint64) error {
	return s.db.DeletePreAuthKey(id)
}

// GetRegistrationCacheEntry retrieves a node registration from cache.
func (s *State) GetRegistrationCacheEntry(id types.RegistrationID) (*types.RegisterNode, bool) {
	entry, found := s.registrationCache.Get(id)
	if !found {
		return nil, false
	}

	return &entry, true
}

// SetRegistrationCacheEntry stores a node registration in cache.
func (s *State) SetRegistrationCacheEntry(id types.RegistrationID, entry types.RegisterNode) {
	s.registrationCache.Set(id, entry)
}

// __BEGIN_CYLONIX_ADD__
// FindRegistrationIDByMachineKey scans the in-memory registration cache for an
// entry whose Node.MachineKey matches the given key. Returns false if no
// matching entry is present. Cylonix uses this for the OIDC followup path
// where the gRPC handler has only the MachineKey from the noise handshake but
// state.HandleNodeFromAuthPath needs a RegistrationID. The cache is small so
// linear scan is fine.
func (s *State) FindRegistrationIDByMachineKey(mk key.MachinePublic) (types.RegistrationID, bool) {
	for id, item := range s.registrationCache.Items() {
		if item.Object.Node.MachineKey == mk {
			return id, true
		}
	}
	return "", false
}

// __END_CYLONIX_ADD__

// logHostinfoValidation logs warnings when hostinfo is nil or has empty hostname.
func logHostinfoValidation(machineKey, nodeKey, username, hostname string, hostinfo *tailcfg.Hostinfo) {
	if hostinfo == nil {
		log.Warn().
			Caller().
			Str("machine.key", machineKey).
			Str("node.key", nodeKey).
			Str("user.name", username).
			Str("generated.hostname", hostname).
			Msg("Registration had nil hostinfo, generated default hostname")
	} else if hostinfo.Hostname == "" {
		log.Warn().
			Caller().
			Str("machine.key", machineKey).
			Str("node.key", nodeKey).
			Str("user.name", username).
			Str("generated.hostname", hostname).
			Msg("Registration had empty hostname, generated default")
	}
}

// preserveNetInfo preserves NetInfo from an existing node for faster DERP connectivity.
// If no existing node is provided, it creates new netinfo from the provided hostinfo.
func preserveNetInfo(existingNode types.NodeView, nodeID types.NodeID, validHostinfo *tailcfg.Hostinfo) *tailcfg.NetInfo {
	var existingHostinfo *tailcfg.Hostinfo
	if existingNode.Valid() {
		existingHostinfo = existingNode.Hostinfo().AsStruct()
	}

	return netInfoFromMapRequest(nodeID, existingHostinfo, validHostinfo)
}

// newNodeParams contains parameters for creating a new node.
type newNodeParams struct {
	User           types.User
	MachineKey     key.MachinePublic
	NodeKey        key.NodePublic
	DiscoKey       key.DiscoPublic
	Hostname       string
	Hostinfo       *tailcfg.Hostinfo
	Endpoints      []netip.AddrPort
	Expiry         *time.Time
	RegisterMethod string

	// Optional: Pre-auth key specific fields
	PreAuthKey *types.PreAuthKey

	// Optional: Existing node for netinfo preservation
	ExistingNodeForNetinfo types.NodeView
}

// authNodeUpdateParams contains parameters for updating an existing node during auth.
type authNodeUpdateParams struct {
	// Node to update; must be valid and in NodeStore.
	ExistingNode types.NodeView
	// Client data: keys, hostinfo, endpoints.
	RegEntry *types.RegisterNode
	// Pre-validated hostinfo; NetInfo preserved from ExistingNode.
	ValidHostinfo *tailcfg.Hostinfo
	// Hostname from hostinfo, or generated from keys if client omits it.
	Hostname string
	// Auth user; may differ from ExistingNode.User() on conversion.
	User *types.User
	// Overrides RegEntry.Node.Expiry; ignored for tagged nodes.
	Expiry *time.Time
	// Only used when IsConvertFromTag=true.
	RegisterMethod string
	// Set true for tagged->user conversion. Affects RegisterMethod and expiry.
	IsConvertFromTag bool
}

// applyAuthNodeUpdate applies common update logic for re-authenticating or converting
// an existing node. It updates the node in NodeStore, processes RequestTags, and
// persists changes to the database.
func (s *State) applyAuthNodeUpdate(params authNodeUpdateParams) (types.NodeView, error) {
	// Log the operation type
	if params.IsConvertFromTag {
		log.Info().
			Str("node.name", params.ExistingNode.Hostname()).
			Uint64("node.id", params.ExistingNode.ID().Uint64()).
			Strs("old.tags", params.ExistingNode.Tags().AsSlice()).
			Msg("Converting tagged node to user-owned node")
	} else {
		log.Info().
			Str("node.name", params.ExistingNode.Hostname()).
			Uint64("node.id", params.ExistingNode.ID().Uint64()).
			Interface("hostinfo", params.RegEntry.Node.Hostinfo).
			Msg("Updating existing node registration via reauth")
	}

	// Process RequestTags during reauth (#2979)
	// Due to json:",omitempty", we treat empty/nil as "clear tags"
	var requestTags []string
	if params.RegEntry.Node.Hostinfo != nil {
		requestTags = params.RegEntry.Node.Hostinfo.RequestTags
	}

	oldTags := params.ExistingNode.Tags().AsSlice()

	// Validate tags BEFORE calling UpdateNode to ensure we don't modify NodeStore
	// if validation fails. This maintains consistency between NodeStore and database.
	rejectedTags := s.validateRequestTags(params.ExistingNode, requestTags)
	if len(rejectedTags) > 0 {
		return types.NodeView{}, fmt.Errorf(
			"%w %v are invalid or not permitted",
			ErrRequestedTagsInvalidOrNotPermitted,
			rejectedTags,
		)
	}

	// Update existing node in NodeStore - validation passed, safe to mutate
	updatedNodeView, ok := s.nodeStore.UpdateNode(params.ExistingNode.ID(), func(node *types.Node) {
		node.NodeKey = params.RegEntry.Node.NodeKey
		node.DiscoKey = params.RegEntry.Node.DiscoKey
		node.Hostname = params.Hostname

		// Preserve NetInfo from existing node when re-registering
		node.Hostinfo = params.ValidHostinfo
		node.Hostinfo.NetInfo = preserveNetInfo(
			params.ExistingNode,
			params.ExistingNode.ID(),
			params.ValidHostinfo,
		)

		node.Endpoints = params.RegEntry.Node.Endpoints
		node.IsOnline = ptr.To(false)
		node.LastSeen = ptr.To(time.Now())

		// Set RegisterMethod - for conversion this is the new method,
		// for reauth we preserve the existing one from regEntry
		if params.IsConvertFromTag {
			node.RegisterMethod = params.RegisterMethod
		} else {
			node.RegisterMethod = params.RegEntry.Node.RegisterMethod
		}

		// Track tagged status BEFORE processing tags
		wasTagged := node.IsTagged()

		// Process tags - may change node.Tags and node.UserID
		// Tags were pre-validated, so this will always succeed (no rejected tags)
		_ = s.processReauthTags(node, requestTags, params.User, oldTags)

		// Handle expiry AFTER tag processing, based on transition
		// This ensures expiry is correctly set/cleared based on the NEW tagged status
		isTagged := node.IsTagged()

		switch {
		case wasTagged && !isTagged:
			// Tagged → Personal: set expiry from client request
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = params.RegEntry.Node.Expiry
			}
		case !wasTagged && isTagged:
			// Personal → Tagged: clear expiry (tagged nodes don't expire)
			node.Expiry = nil
		case params.IsConvertFromTag:
			// Explicit conversion from tagged to user-owned: set expiry from client request
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = params.RegEntry.Node.Expiry
			}
		case !isTagged:
			// Personal → Personal: update expiry from client
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = params.RegEntry.Node.Expiry
			}
		}
		// Tagged → Tagged: keep existing expiry (nil) - no action needed
	})

	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, params.ExistingNode.ID())
	}

	// Persist to database
	// Omit AuthKeyID/AuthKey to prevent stale PreAuthKey references from causing FK errors.
	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := tx.Omit("AuthKeyID", "AuthKey").Updates(updatedNodeView.AsStruct()).Error
		if err != nil {
			return nil, fmt.Errorf("failed to save node: %w", err)
		}

		return nil, nil //nolint:nilnil // side-effect only write
	})
	if err != nil {
		return types.NodeView{}, err
	}

	// Log completion
	if params.IsConvertFromTag {
		log.Trace().
			Str("node.name", updatedNodeView.Hostname()).
			Uint64("node.id", updatedNodeView.ID().Uint64()).
			Str("node.key", updatedNodeView.NodeKey().ShortString()).
			Msg("Tagged node converted to user-owned")
	} else {
		log.Trace().
			Str("node.name", updatedNodeView.Hostname()).
			Uint64("node.id", updatedNodeView.ID().Uint64()).
			Str("node.key", updatedNodeView.NodeKey().ShortString()).
			Msg("Node re-authorized")
	}

	return updatedNodeView, nil
}

// createAndSaveNewNode creates a new node, allocates IPs, saves to DB, and adds to NodeStore.
// It preserves netinfo from an existing node if one is provided (for faster DERP connectivity).
func (s *State) createAndSaveNewNode(params newNodeParams) (types.NodeView, error) {
	// Preserve NetInfo from existing node if available
	if params.Hostinfo != nil {
		params.Hostinfo.NetInfo = preserveNetInfo(
			params.ExistingNodeForNetinfo,
			types.NodeID(0),
			params.Hostinfo,
		)
	}

	// Prepare the node for registration
	nodeToRegister := types.Node{
		Hostname:       params.Hostname,
		MachineKey:     params.MachineKey,
		NodeKey:        params.NodeKey,
		DiscoKey:       params.DiscoKey,
		Hostinfo:       params.Hostinfo,
		Endpoints:      params.Endpoints,
		LastSeen:       ptr.To(time.Now()),
		RegisterMethod: params.RegisterMethod,
		Expiry:         params.Expiry,
	}

	// Assign ownership based on PreAuthKey
	if params.PreAuthKey != nil {
		if params.PreAuthKey.IsTagged() {
			// TAGGED NODE
			// Tags from PreAuthKey are assigned ONLY during initial authentication
			nodeToRegister.Tags = params.PreAuthKey.Proto().GetAclTags()

			// Set UserID to track "created by" (who created the PreAuthKey)
			if params.PreAuthKey.UserID != nil {
				nodeToRegister.UserID = params.PreAuthKey.UserID
				nodeToRegister.User = params.PreAuthKey.User
			}
			// If PreAuthKey.UserID is nil, the node is "orphaned" (system-created)

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil
		} else {
			// USER-OWNED NODE
			nodeToRegister.UserID = &params.PreAuthKey.User.ID
			nodeToRegister.User = params.PreAuthKey.User
			nodeToRegister.Tags = nil
		}

		nodeToRegister.AuthKey = params.PreAuthKey
		nodeToRegister.AuthKeyID = &params.PreAuthKey.ID
	} else {
		// Non-PreAuthKey registration (OIDC, CLI) - always user-owned
		nodeToRegister.UserID = &params.User.ID
		nodeToRegister.User = &params.User
		nodeToRegister.Tags = nil
	}

	// Reject advertise-tags for PreAuthKey registrations early, before any resource allocation.
	// PreAuthKey nodes get their tags from the key itself, not from client requests.
	if params.PreAuthKey != nil && params.Hostinfo != nil && len(params.Hostinfo.RequestTags) > 0 {
		return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, params.Hostinfo.RequestTags)
	}

	// Process RequestTags (from tailscale up --advertise-tags) ONLY for non-PreAuthKey registrations.
	// Validate early before IP allocation to avoid resource leaks on failure.
	if params.PreAuthKey == nil && params.Hostinfo != nil && len(params.Hostinfo.RequestTags) > 0 {
		// Validate all tags before applying - reject if any tag is not permitted
		rejectedTags := s.validateRequestTags(nodeToRegister.View(), params.Hostinfo.RequestTags)
		if len(rejectedTags) > 0 {
			return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, rejectedTags)
		}

		// All tags are approved - apply them
		approvedTags := params.Hostinfo.RequestTags
		if len(approvedTags) > 0 {
			nodeToRegister.Tags = approvedTags
			slices.Sort(nodeToRegister.Tags)
			nodeToRegister.Tags = slices.Compact(nodeToRegister.Tags)

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil

			log.Info().
				Str("node.name", nodeToRegister.Hostname).
				Strs("tags", nodeToRegister.Tags).
				Msg("approved advertise-tags during registration")
		}
	}

	// Validate before saving
	err := validateNodeOwnership(&nodeToRegister)
	if err != nil {
		return types.NodeView{}, err
	}

	// __BEGIN_CYLONIX_MOD__ Allocate new IPs. Cylonix wires its ipdrawer-backed
	// allocator into cfg.IPAllocator; when present we delegate so addresses
	// are tracked in the cylonix-side IP DB rather than the headscale-local
	// pool. Upstream calls s.ipAlloc.Next() unconditionally.
	var ipv4, ipv6 *netip.Addr
	if s.cfg != nil && s.cfg.IPAllocator != nil {
		mk := nodeToRegister.MachineKey
		ipv4, ipv6, err = s.cfg.IPAllocator.NextFor(nodeToRegister.User, &mk, nil, nil)
	} else {
		ipv4, ipv6, err = s.ipAlloc.Next()
	}
	if err != nil {
		return types.NodeView{}, fmt.Errorf("allocating IPs: %w", err)
	}
	// __END_CYLONIX_MOD__

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Ensure unique given name if not set
	if nodeToRegister.GivenName == "" {
		givenName, err := hsdb.EnsureUniqueGivenName(s.db.DB, nodeToRegister.Hostname)
		if err != nil {
			return types.NodeView{}, fmt.Errorf("failed to ensure unique given name: %w", err)
		}

		nodeToRegister.GivenName = givenName
	}

	// New node - database first to get ID, then NodeStore.
	// __CYLONIX_MOD__ Inside the tx we call hsdb.RegisterNodePreAdd to do the
	// cylonix tenant-stamping (NodeHandler.PreAdd → wg_info row, NodeHandler
	// .NetworkDomain → node.NetworkDomain, GenerateGivenName) the same way
	// the gRPC RegisterNode path does. Then stamp node.Namespace from the
	// user — same as the pre-merge `if node.User != nil { node.Namespace =
	// node.User.GetNamespace() }` in db.RegisterNode (db/node.go:755). The
	// v0.28 auth-path flow bypasses RegisterNode, so without this block the
	// nodes row lands with empty namespace/network_domain and AuthScope
	// filtering on the API side returns zero results.
	savedNode, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		if s.cfg != nil && s.cfg.NodeHandler != nil {
			if err := hsdb.RegisterNodePreAdd(tx, &nodeToRegister, s.cfg.NodeHandler); err != nil {
				// Free the IP we just allocated since registration is being
				// aborted before the node is saved.
				if s.cfg.IPAllocator != nil && ipv4 != nil {
					if frErr := s.cfg.IPAllocator.FreeFor(ipv4, nodeToRegister.User, &nodeToRegister.MachineKey); frErr != nil {
						log.Warn().Err(frErr).Msg("failed to free IP after RegisterNodePreAdd error")
					}
				}
				return nil, fmt.Errorf("RegisterNodePreAdd: %w", err)
			}
		}
		if nodeToRegister.User != nil {
			nodeToRegister.Namespace = nodeToRegister.User.GetNamespace()
		}
		err := tx.Save(&nodeToRegister).Error
		if err != nil {
			return nil, fmt.Errorf("failed to save node: %w", err)
		}

		if params.PreAuthKey != nil && !params.PreAuthKey.Reusable {
			err := hsdb.UsePreAuthKey(tx, params.PreAuthKey)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return &nodeToRegister, nil
	})
	if err != nil {
		return types.NodeView{}, err
	}

	// Add to NodeStore after database creates the ID
	return s.nodeStore.PutNode(*savedNode), nil
}

// validateRequestTags validates that the requested tags are permitted for the node.
// This should be called BEFORE UpdateNode to ensure we don't modify NodeStore
// if validation fails. Returns the list of rejected tags (empty if all valid).
func (s *State) validateRequestTags(node types.NodeView, requestTags []string) []string {
	// Empty tags = clear tags, always permitted
	if len(requestTags) == 0 {
		return nil
	}

	var rejectedTags []string

	for _, tag := range requestTags {
		if !s.polMan.NodeCanHaveTag(node, tag) {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	return rejectedTags
}

// processReauthTags handles tag changes during node re-authentication.
// It processes RequestTags from the client and updates node tags accordingly.
// Returns rejected tags (if any) for post-validation error handling.
func (s *State) processReauthTags(
	node *types.Node,
	requestTags []string,
	user *types.User,
	oldTags []string,
) []string {
	wasAuthKeyTagged := node.AuthKey != nil && node.AuthKey.IsTagged()

	logEvent := log.Debug().
		Uint64("node.id", uint64(node.ID)).
		Str("node.name", node.Hostname).
		Strs("request.tags", requestTags).
		Strs("current.tags", node.Tags).
		Bool("is.tagged", node.IsTagged()).
		Bool("was.authkey.tagged", wasAuthKeyTagged)
	logEvent.Msg("Processing RequestTags during reauth")

	// Empty RequestTags means untag node (transition to user-owned)
	if len(requestTags) == 0 {
		if node.IsTagged() {
			log.Info().
				Uint64("node.id", uint64(node.ID)).
				Str("node.name", node.Hostname).
				Strs("removed.tags", node.Tags).
				Str("user.name", user.Name).
				Bool("was.authkey.tagged", wasAuthKeyTagged).
				Msg("Reauth: removing all tags, returning node ownership to user")

			node.Tags = []string{}
			node.UserID = &user.ID
			node.User = user
		}

		return nil
	}

	// Non-empty RequestTags: validate and apply
	var approvedTags, rejectedTags []string

	for _, tag := range requestTags {
		if s.polMan.NodeCanHaveTag(node.View(), tag) {
			approvedTags = append(approvedTags, tag)
		} else {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	if len(rejectedTags) > 0 {
		log.Warn().
			Uint64("node.id", uint64(node.ID)).
			Str("node.name", node.Hostname).
			Strs("rejected.tags", rejectedTags).
			Msg("Reauth: requested tags are not permitted")

		return rejectedTags
	}

	if len(approvedTags) > 0 {
		slices.Sort(approvedTags)
		approvedTags = slices.Compact(approvedTags)

		wasTagged := node.IsTagged()
		node.Tags = approvedTags

		// Note: UserID is preserved as "created by" tracking, consistent with SetNodeTags
		if !wasTagged {
			log.Info().
				Uint64("node.id", uint64(node.ID)).
				Str("node.name", node.Hostname).
				Strs("new.tags", approvedTags).
				Str("old.user", user.Name).
				Msg("Reauth: applying tags, transferring node to tagged-devices")
		} else {
			log.Info().
				Uint64("node.id", uint64(node.ID)).
				Str("node.name", node.Hostname).
				Strs("old.tags", oldTags).
				Strs("new.tags", approvedTags).
				Msg("Reauth: updating tags on already-tagged node")
		}
	}

	return nil
}

// HandleNodeFromAuthPath handles node registration through authentication flow (like OIDC).
func (s *State) HandleNodeFromAuthPath(
	registrationID types.RegistrationID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (types.NodeView, change.Change, error) {
	// Get the registration entry from cache
	regEntry, ok := s.GetRegistrationCacheEntry(registrationID)
	if !ok {
		return types.NodeView{}, change.Change{}, hsdb.ErrNodeNotFoundRegistrationCache
	}

	// Get the user
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("failed to find user: %w", err)
	}

	// Ensure we have a valid hostname from the registration cache entry
	hostname := util.EnsureHostname(
		regEntry.Node.Hostinfo,
		regEntry.Node.MachineKey.String(),
		regEntry.Node.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regEntry.Node.Hostinfo, &tailcfg.Hostinfo{})
	validHostinfo.Hostname = hostname

	logHostinfoValidation(
		regEntry.Node.MachineKey.ShortString(),
		regEntry.Node.NodeKey.String(),
		user.Name,
		hostname,
		regEntry.Node.Hostinfo,
	)

	// Lookup existing nodes
	machineKey := regEntry.Node.MachineKey
	existingNodeSameUser, _ := s.nodeStore.GetNodeByMachineKey(machineKey, types.UserID(user.ID))
	existingNodeAnyUser, _ := s.nodeStore.GetNodeByMachineKeyAnyUser(machineKey)

	// Named conditions - describe WHAT we found, not HOW we check it
	nodeExistsForSameUser := existingNodeSameUser.Valid()
	nodeExistsForAnyUser := existingNodeAnyUser.Valid()
	existingNodeIsTagged := nodeExistsForAnyUser && existingNodeAnyUser.IsTagged()
	existingNodeOwnedByOtherUser := nodeExistsForAnyUser &&
		!existingNodeIsTagged &&
		existingNodeAnyUser.UserID().Get() != user.ID

	// Create logger with common fields for all auth operations
	logger := log.With().
		Str("registration_id", registrationID.String()).
		Str("user.name", user.Name).
		Str("machine.key", machineKey.ShortString()).
		Str("method", registrationMethod).
		Logger()

	// Common params for update operations
	updateParams := authNodeUpdateParams{
		RegEntry:       regEntry,
		ValidHostinfo:  validHostinfo,
		Hostname:       hostname,
		User:           user,
		Expiry:         expiry,
		RegisterMethod: registrationMethod,
	}

	var finalNode types.NodeView

	if nodeExistsForSameUser {
		updateParams.ExistingNode = existingNodeSameUser

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	} else if existingNodeIsTagged {
		updateParams.ExistingNode = existingNodeAnyUser
		updateParams.IsConvertFromTag = true

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	} else if existingNodeOwnedByOtherUser {
		oldUser := existingNodeAnyUser.User()

		logger.Info().
			Str("existing.node.name", existingNodeAnyUser.Hostname()).
			Uint64("existing.node.id", existingNodeAnyUser.ID().Uint64()).
			Str("old.user", oldUser.Name()).
			Msg("Creating new node for different user (same machine key exists for another user)")

		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regEntry, hostname, validHostinfo,
			expiry, registrationMethod, existingNodeAnyUser,
		)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	} else {
		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regEntry, hostname, validHostinfo,
			expiry, registrationMethod, types.NodeView{},
		)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	}

	// Signal to waiting clients
	regEntry.SendAndClose(finalNode.AsStruct())

	// Delete from registration cache
	s.registrationCache.Delete(registrationID)

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager users: %w", err)
	}

	// __CYLONIX_MOD__ scope cache invalidation to the new node's tailnet
	nodesChange, err := s.updatePolicyManagerNodesForTailnet(finalNode.NetworkDomain())
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager nodes: %w", err)
	}

	var c change.Change
	if !usersChange.IsEmpty() || !nodesChange.IsEmpty() {
		c = change.PolicyChange()
	} else {
		c = change.NodeAdded(finalNode.ID())
	}

	return finalNode, c, nil
}

// createNewNodeFromAuth creates a new node during auth callback.
// This is used for both new registrations and when a machine already has a node
// for a different user.
func (s *State) createNewNodeFromAuth(
	logger zerolog.Logger,
	user *types.User,
	regEntry *types.RegisterNode,
	hostname string,
	validHostinfo *tailcfg.Hostinfo,
	expiry *time.Time,
	registrationMethod string,
	existingNodeForNetinfo types.NodeView,
) (types.NodeView, error) {
	logger.Debug().
		Interface("expiry", expiry).
		Msg("Registering new node from auth callback")

	return s.createAndSaveNewNode(newNodeParams{
		User:                   *user,
		MachineKey:             regEntry.Node.MachineKey,
		NodeKey:                regEntry.Node.NodeKey,
		DiscoKey:               regEntry.Node.DiscoKey,
		Hostname:               hostname,
		Hostinfo:               validHostinfo,
		Endpoints:              regEntry.Node.Endpoints,
		Expiry:                 cmp.Or(expiry, regEntry.Node.Expiry),
		RegisterMethod:         registrationMethod,
		ExistingNodeForNetinfo: existingNodeForNetinfo,
	})
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, change.Change, error) {
	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// Helper to get username for logging (handles nil User for tags-only keys)
	pakUsername := func() string {
		if pak.User != nil {
			return pak.User.Username()
		}

		return types.TaggedDevices.Name
	}

	// Check if node exists with same machine key before validating the key.
	// For #2830: container restarts send the same pre-auth key which may be used/expired.
	// Skip validation for existing nodes re-registering with the same NodeKey, as the
	// key was only needed for initial authentication. NodeKey rotation requires validation.
	//
	// For tags-only keys (pak.User == nil), we skip the user-based lookup since there's
	// no user to match against. These keys create tagged nodes without user ownership.
	var existingNodeSameUser types.NodeView

	var existsSameUser bool

	if pak.User != nil {
		existingNodeSameUser, existsSameUser = s.nodeStore.GetNodeByMachineKey(machineKey, types.UserID(pak.User.ID))
	}

	// For existing nodes, skip validation if:
	// 1. MachineKey matches (cryptographic proof of machine identity)
	// 2. User matches (from the PAK being used)
	// 3. Not a NodeKey rotation (rotation requires fresh validation)
	//
	// Security: MachineKey is the cryptographic identity. If someone has the MachineKey,
	// they control the machine. The PAK was only needed to authorize initial join.
	// We don't check which specific PAK was used originally because:
	// - Container restarts may use different PAKs (e.g., env var changed)
	// - Original PAK may be deleted
	// - MachineKey + User is sufficient to prove this is the same node
	//
	// Note: For tags-only keys, existsSameUser is always false, so we always validate.
	isExistingNodeReregistering := existsSameUser && existingNodeSameUser.Valid()

	// Check if this is a NodeKey rotation (different NodeKey)
	isNodeKeyRotation := existsSameUser && existingNodeSameUser.Valid() &&
		existingNodeSameUser.NodeKey() != regReq.NodeKey

	if isExistingNodeReregistering && !isNodeKeyRotation {
		// Existing node re-registering with same NodeKey: skip validation.
		// Pre-auth keys are only needed for initial authentication. Critical for
		// containers that run "tailscale up --authkey=KEY" on every restart.
		log.Debug().
			Caller().
			Uint64("node.id", existingNodeSameUser.ID().Uint64()).
			Str("node.name", existingNodeSameUser.Hostname()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key.existing", existingNodeSameUser.NodeKey().ShortString()).
			Str("node.key.request", regReq.NodeKey.ShortString()).
			Uint64("authkey.id", pak.ID).
			Bool("authkey.used", pak.Used).
			Bool("authkey.expired", pak.Expiration != nil && pak.Expiration.Before(time.Now())).
			Bool("authkey.reusable", pak.Reusable).
			Bool("nodekey.rotation", isNodeKeyRotation).
			Msg("Existing node re-registering with same NodeKey and auth key, skipping validation")
	} else {
		// New node or NodeKey rotation: require valid auth key.
		err = pak.Validate()
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	}

	// Ensure we have a valid hostname - handle nil/empty cases
	hostname := util.EnsureHostname(
		regReq.Hostinfo,
		machineKey.String(),
		regReq.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regReq.Hostinfo, &tailcfg.Hostinfo{})
	validHostinfo.Hostname = hostname

	logHostinfoValidation(
		machineKey.ShortString(),
		regReq.NodeKey.ShortString(),
		pakUsername(),
		hostname,
		regReq.Hostinfo,
	)

	log.Debug().
		Caller().
		Str("node.name", hostname).
		Str("machine.key", machineKey.ShortString()).
		Str("node.key", regReq.NodeKey.ShortString()).
		Str("user.name", pakUsername()).
		Msg("Registering node with pre-auth key")

	var finalNode types.NodeView

	// If this node exists for this user, update the node in place.
	// Note: For tags-only keys (pak.User == nil), existsSameUser is always false.
	if existsSameUser && existingNodeSameUser.Valid() {
		log.Trace().
			Caller().
			Str("node.name", existingNodeSameUser.Hostname()).
			Uint64("node.id", existingNodeSameUser.ID().Uint64()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", existingNodeSameUser.NodeKey().ShortString()).
			Str("user.name", pakUsername()).
			Msg("Node re-registering with existing machine key and user, updating in place")

		// Update existing node - NodeStore first, then database
		updatedNodeView, ok := s.nodeStore.UpdateNode(existingNodeSameUser.ID(), func(node *types.Node) {
			node.NodeKey = regReq.NodeKey
			node.Hostname = hostname

			// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
			// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

			// Preserve NetInfo from existing node when re-registering
			node.Hostinfo = validHostinfo
			node.Hostinfo.NetInfo = preserveNetInfo(existingNodeSameUser, existingNodeSameUser.ID(), validHostinfo)

			node.RegisterMethod = util.RegisterMethodAuthKey

			// CRITICAL: Tags from PreAuthKey are ONLY applied during initial authentication
			// On re-registration, we MUST NOT change tags or node ownership
			// The node keeps whatever tags/user ownership it already has
			//
			// Only update AuthKey reference
			node.AuthKey = pak
			node.AuthKeyID = &pak.ID
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())

			// Tagged nodes keep their existing expiry (disabled).
			// User-owned nodes update expiry from the client request.
			if !node.IsTagged() {
				node.Expiry = &regReq.Expiry
			}
		})

		if !ok {
			return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, existingNodeSameUser.ID())
		}

		_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			// Use Updates() to preserve fields not modified by UpdateNode.
			// Omit AuthKeyID/AuthKey to prevent stale PreAuthKey references from causing FK errors.
			err := tx.Omit("AuthKeyID", "AuthKey").Updates(updatedNodeView.AsStruct()).Error
			if err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}

			if !pak.Reusable {
				err = hsdb.UsePreAuthKey(tx, pak)
				if err != nil {
					return nil, fmt.Errorf("using pre auth key: %w", err)
				}
			}

			return nil, nil
		})
		if err != nil {
			return types.NodeView{}, change.Change{}, fmt.Errorf("writing node to database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node.name", updatedNodeView.Hostname()).
			Uint64("node.id", updatedNodeView.ID().Uint64()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", updatedNodeView.NodeKey().ShortString()).
			Str("user.name", pakUsername()).
			Msg("Node re-authorized")

		finalNode = updatedNodeView
	} else {
		// Node does not exist for this user with this machine key
		// Check if node exists with this machine key for a different user
		existingNodeAnyUser, existsAnyUser := s.nodeStore.GetNodeByMachineKeyAnyUser(machineKey)

		// For user-owned keys, check if node exists for a different user
		// For tags-only keys (pak.User == nil), this check is skipped
		if pak.User != nil && existsAnyUser && existingNodeAnyUser.Valid() && existingNodeAnyUser.UserID().Get() != pak.User.ID {
			// Node exists but belongs to a different user
			// Create a NEW node for the new user (do not transfer)
			// This allows the same machine to have separate node identities per user
			oldUser := existingNodeAnyUser.User()
			log.Info().
				Caller().
				Str("existing.node.name", existingNodeAnyUser.Hostname()).
				Uint64("existing.node.id", existingNodeAnyUser.ID().Uint64()).
				Str("machine.key", machineKey.ShortString()).
				Str("old.user", oldUser.Name()).
				Str("new.user", pakUsername()).
				Msg("Creating new node for different user (same machine key exists for another user)")
		}

		// This is a new node - create it
		// For user-owned keys: create for the user
		// For tags-only keys: create as tagged node (createAndSaveNewNode handles this via PreAuthKey)

		// Create and save new node
		// Note: For tags-only keys, User is empty but createAndSaveNewNode uses PreAuthKey for ownership
		var pakUser types.User
		if pak.User != nil {
			pakUser = *pak.User
		}

		var err error

		finalNode, err = s.createAndSaveNewNode(newNodeParams{
			User:                   pakUser,
			MachineKey:             machineKey,
			NodeKey:                regReq.NodeKey,
			DiscoKey:               key.DiscoPublic{}, // DiscoKey not available in RegisterRequest
			Hostname:               hostname,
			Hostinfo:               validHostinfo,
			Endpoints:              nil, // Endpoints not available in RegisterRequest
			Expiry:                 &regReq.Expiry,
			RegisterMethod:         util.RegisterMethodAuthKey,
			PreAuthKey:             pak,
			ExistingNodeForNetinfo: cmp.Or(existingNodeAnyUser, types.NodeView{}),
		})
		if err != nil {
			return types.NodeView{}, change.Change{}, fmt.Errorf("creating new node: %w", err)
		}
	}

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager users: %w", err)
	}

	// __CYLONIX_MOD__ scope cache invalidation to the new node's tailnet
	nodesChange, err := s.updatePolicyManagerNodesForTailnet(finalNode.NetworkDomain())
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager nodes: %w", err)
	}

	var c change.Change
	if !usersChange.IsEmpty() || !nodesChange.IsEmpty() {
		c = change.PolicyChange()
	} else {
		c = change.NodeAdded(finalNode.ID())
	}

	return finalNode, c, nil
}

// updatePolicyManagerUsers updates the policy manager with current users.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for users.
// updatePolicyManagerUsers refreshes the policy manager with current user data.
func (s *State) updatePolicyManagerUsers() (change.Change, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("listing users for policy update: %w", err)
	}

	log.Debug().Caller().Int("user.count", len(users)).Msg("Policy manager user update initiated because user list modification detected")

	changed, err := s.polMan.SetUsers(users)
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager users: %w", err)
	}

	log.Debug().Caller().Bool("policy.changed", changed).Msg("Policy manager user update completed because SetUsers operation finished")

	if changed {
		return change.PolicyChange(), nil
	}

	return change.Change{}, nil
}

// UpdatePolicyManagerUsersForTest updates the policy manager's user cache.
// This is exposed for testing purposes to sync the policy manager after
// creating test users via CreateUserForTest().
func (s *State) UpdatePolicyManagerUsersForTest() error {
	_, err := s.updatePolicyManagerUsers()
	return err
}

// updatePolicyManagerNodes updates the policy manager with current nodes.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
// updatePolicyManagerNodes refreshes the policy manager with current node data.
//
// __CYLONIX_MOD__ Equivalent to updatePolicyManagerNodesForTailnet("") — the
// "I don't know which tailnet changed" path that invalidates every tailnet.
func (s *State) updatePolicyManagerNodes() (change.Change, error) {
	return s.updatePolicyManagerNodesForTailnet("")
}

// __BEGIN_CYLONIX_ADD__
// updatePolicyManagerNodesForTailnet is the per-tailnet variant of
// updatePolicyManagerNodes. When `tailnet` is non-empty, only that
// tailnet's peer cache (plus its share-edge neighbours, via
// invalidateTailnetCascade) is marked stale. When `tailnet` is empty,
// every tailnet's cache is invalidated — used by ReloadPolicy and
// callers that don't have a specific tailnet (or that affect more than
// one).
//
// The polMan.SetNodes call still runs against the full ListNodes()
// snapshot regardless of `tailnet`: today the policy manager holds a
// single global filter, so the SetNodes diff cannot be narrowed without
// risking stale derived state (tag-owner map, autoapprover map,
// SSHPolicy cache). Only the cache invalidation is scoped.
func (s *State) updatePolicyManagerNodesForTailnet(tailnet string) (change.Change, error) {
	nodes := s.ListNodes()

	changed, err := s.polMan.SetNodes(nodes)
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager nodes: %w", err)
	}

	if changed {
		// Policy-affecting node changes (tags, user, IPs) affect ACL
		// visibility. When the caller knows the affected tailnet, only
		// that tailnet's cascade is invalidated. Otherwise every
		// tailnet is invalidated. The next per-tailnet ListPeers
		// triggers a lazy rebuild via rebuildTailnet. The global
		// RebuildPeerMaps call is retained as a safety net for the
		// no-NodeHandler case (single-tenant deployments) where
		// ListPeers reads peersByNode directly.
		if tailnet != "" {
			s.invalidateTailnetCascade(tailnet)
		} else {
			s.invalidateAllTailnetCaches()
		}
		s.nodeStore.RebuildPeerMaps()
		return change.PolicyChange(), nil
	}

	return change.Change{}, nil
}

// __END_CYLONIX_ADD__

// PingDB checks if the database connection is healthy.
func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// autoApproveNodes mass approves routes on all nodes. It is _only_ intended for
// use when the policy is replaced. It is not sending or reporting any changes
// or updates as we send full updates after replacing the policy.
// TODO(kradalby): This is kind of messy, maybe this is another +1
// for an event bus. See example comments here.
// autoApproveNodes automatically approves nodes based on policy rules.
func (s *State) autoApproveNodes() ([]change.Change, error) {
	nodes := s.ListNodes()

	// Approve routes concurrently, this should make it likely
	// that the writes end in the same batch in the nodestore write.
	var (
		errg errgroup.Group
		cs   []change.Change
		mu   sync.Mutex
	)
	for _, nv := range nodes.All() {
		errg.Go(func() error {
			approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
			if changed {
				log.Debug().
					Uint64("node.id", nv.ID().Uint64()).
					Str("node.name", nv.Hostname()).
					Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
					Strs("routes.approved.new", util.PrefixesToString(approved)).
					Msg("Routes auto-approved by policy")

				_, c, err := s.SetApprovedRoutes(nv.ID(), approved)
				if err != nil {
					return err
				}

				mu.Lock()

				cs = append(cs, c)

				mu.Unlock()
			}

			return nil
		})
	}

	err := errg.Wait()
	if err != nil {
		return nil, err
	}

	return cs, nil
}

// UpdateNodeFromMapRequest processes a MapRequest and updates the node.
// TODO(kradalby): This is essentially a patch update that could be sent directly to nodes,
// which means we could shortcut the whole change thing if there are no other important updates.
// When a field is added to this function, remember to also add it to:
// - node.PeerChangeFromMapRequest
// - node.ApplyPeerChange
// - logTracePeerChange in poll.go.
func (s *State) UpdateNodeFromMapRequest(id types.NodeID, req tailcfg.MapRequest) (change.Change, error) {
	log.Trace().
		Caller().
		Uint64("node.id", id.Uint64()).
		Interface("request", req).
		Msg("Processing MapRequest for node")

	var (
		routeChange        bool
		hostinfoChanged    bool
		needsRouteApproval bool
		autoApprovedRoutes []netip.Prefix
		endpointChanged    bool
		derpChanged        bool
	)

	// __BEGIN_CYLONIX_MOD__ Backfill a v6 address for nodes that were assigned
	// only a v4 address before IPv6 support existed. Many devices reconnect by
	// polling for their netmap without re-registering, so this path (in addition
	// to PreAdd) must allocate the missing v6. The allocation is an ipdrawer
	// network call, so it is done OUTSIDE the NodeStore lock; the result is
	// applied inside the UpdateNode callback below and persisted by
	// persistNodeToDB.
	var backfilledIPv6 *netip.Addr
	if s.cfg != nil && s.cfg.NodeHandler != nil {
		if cur, ok := s.GetNodeByID(id); ok && cur.Valid() {
			if node := cur.AsStruct(); node.IPv6 == nil {
				v6, err := s.cfg.NodeHandler.BackfillNodeIPv6(node)
				if err != nil {
					log.Warn().Err(err).Uint64("node.id", id.Uint64()).
						Msg("cylonix BackfillNodeIPv6 failed; continuing without v6")
				} else {
					backfilledIPv6 = v6
				}
			}
		}
	}
	// __END_CYLONIX_MOD__

	// We need to ensure we update the node as it is in the NodeStore at
	// the time of the request.
	updatedNode, ok := s.nodeStore.UpdateNode(id, func(currentNode *types.Node) {
		// __BEGIN_CYLONIX_MOD__ Apply the backfilled v6 so it flows into
		// updatedNode and is saved by persistNodeToDB below.
		if backfilledIPv6 != nil {
			currentNode.IPv6 = backfilledIPv6
		}
		// __END_CYLONIX_MOD__
		peerChange := currentNode.PeerChangeFromMapRequest(req)

		// Track what specifically changed
		endpointChanged = peerChange.Endpoints != nil
		derpChanged = peerChange.DERPRegion != 0
		hostinfoChanged = !hostinfoEqual(currentNode.View(), req.Hostinfo)

		// Get the correct NetInfo to use
		netInfo := netInfoFromMapRequest(id, currentNode.Hostinfo, req.Hostinfo)
		if req.Hostinfo != nil {
			req.Hostinfo.NetInfo = netInfo
		} else {
			req.Hostinfo = &tailcfg.Hostinfo{NetInfo: netInfo}
		}

		// Re-check hostinfoChanged after potential NetInfo preservation
		hostinfoChanged = !hostinfoEqual(currentNode.View(), req.Hostinfo)

		// If there is no changes and nothing to save,
		// return early.
		if peerChangeEmpty(peerChange) && !hostinfoChanged {
			return
		}

		// Calculate route approval before NodeStore update to avoid calling View() inside callback
		var hasNewRoutes bool
		if hi := req.Hostinfo; hi != nil {
			hasNewRoutes = len(hi.RoutableIPs) > 0
		}

		needsRouteApproval = hostinfoChanged && (routesChanged(currentNode.View(), req.Hostinfo) || (hasNewRoutes && len(currentNode.ApprovedRoutes) == 0))
		if needsRouteApproval {
			// Extract announced routes from request
			var announcedRoutes []netip.Prefix
			if req.Hostinfo != nil {
				announcedRoutes = req.Hostinfo.RoutableIPs
			}

			// Apply policy-based auto-approval if routes are announced
			if len(announcedRoutes) > 0 {
				autoApprovedRoutes, routeChange = policy.ApproveRoutesWithPolicy(
					s.polMan,
					currentNode.View(),
					currentNode.ApprovedRoutes,
					announcedRoutes,
				)
			}
		}

		// Log when routes change but approval doesn't
		if hostinfoChanged && !routeChange {
			if hi := req.Hostinfo; hi != nil {
				if routesChanged(currentNode.View(), hi) {
					log.Debug().
						Caller().
						Uint64("node.id", id.Uint64()).
						Strs("oldAnnouncedRoutes", util.PrefixesToString(currentNode.AnnouncedRoutes())).
						Strs("newAnnouncedRoutes", util.PrefixesToString(hi.RoutableIPs)).
						Strs("approvedRoutes", util.PrefixesToString(currentNode.ApprovedRoutes)).
						Bool("routeChange", routeChange).
						Msg("announced routes changed but approved routes did not")
				}
			}
		}

		currentNode.ApplyPeerChange(&peerChange)

		if hostinfoChanged {
			// The node might not set NetInfo if it has not changed and if
			// the full HostInfo object is overwritten, the information is lost.
			// If there is no NetInfo, keep the previous one.
			// From 1.66 the client only sends it if changed:
			// https://github.com/tailscale/tailscale/commit/e1011f138737286ecf5123ff887a7a5800d129a2
			// TODO(kradalby): evaluate if we need better comparing of hostinfo
			// before we take the changes.
			// NetInfo preservation has already been handled above before early return check
			currentNode.Hostinfo = req.Hostinfo
			currentNode.ApplyHostnameFromHostInfo(req.Hostinfo)

			if routeChange {
				// Apply pre-calculated route approval
				// Always apply the route approval result to ensure consistency,
				// regardless of whether the policy evaluation detected changes.
				// This fixes the bug where routes weren't properly cleared when
				// auto-approvers were removed from the policy.
				log.Info().
					Uint64("node.id", id.Uint64()).
					Strs("oldApprovedRoutes", util.PrefixesToString(currentNode.ApprovedRoutes)).
					Strs("newApprovedRoutes", util.PrefixesToString(autoApprovedRoutes)).
					Bool("routeChanged", routeChange).
					Msg("applying route approval results")
			}
		}
	})

	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	if routeChange {
		log.Debug().
			Uint64("node.id", id.Uint64()).
			Strs("autoApprovedRoutes", util.PrefixesToString(autoApprovedRoutes)).
			Msg("Persisting auto-approved routes from MapRequest")

		// SetApprovedRoutes will update both database and PrimaryRoutes table
		_, c, err := s.SetApprovedRoutes(id, autoApprovedRoutes)
		if err != nil {
			return change.Change{}, fmt.Errorf("persisting auto-approved routes: %w", err)
		}

		// If SetApprovedRoutes resulted in a policy change, return it
		if !c.IsEmpty() {
			return c, nil
		}
	} // Continue with the rest of the processing using the updated node

	// Handle route changes after NodeStore update.
	// Update routes if announced routes changed (even if approved routes stayed the same)
	// because SubnetRoutes is the intersection of announced AND approved routes.
	nodeRouteChange := s.maybeUpdateNodeRoutes(id, updatedNode, hostinfoChanged, needsRouteApproval, routeChange, req.Hostinfo)

	_, policyChange, err := s.persistNodeToDB(updatedNode)
	if err != nil {
		return change.Change{}, fmt.Errorf("saving to database: %w", err)
	}

	if policyChange.IsFull() {
		return policyChange, nil
	}

	if !nodeRouteChange.IsEmpty() {
		return nodeRouteChange, nil
	}

	// __BEGIN_CYLONIX_MOD__ A freshly backfilled IPv6 changes the node's
	// addresses. The lightweight endpoint/DERP patch path below carries ONLY
	// endpoints/DERP, not address changes, so when a backfill coincides with a
	// reconnect (endpoint change) peers would never learn the new v6. Force a
	// full node update so the new address propagates to all peers' netmaps.
	if backfilledIPv6 != nil {
		return change.NodeAdded(id), nil
	}
	// __END_CYLONIX_MOD__

	// Determine the most specific change type based on what actually changed.
	// This allows us to send lightweight patch updates instead of full map responses.
	return buildMapRequestChangeResponse(id, updatedNode, hostinfoChanged, endpointChanged, derpChanged)
}

// buildMapRequestChangeResponse determines the appropriate response type for a MapRequest update.
// Hostinfo changes require a full update, while endpoint/DERP changes can use lightweight patches.
func buildMapRequestChangeResponse(
	id types.NodeID,
	node types.NodeView,
	hostinfoChanged, endpointChanged, derpChanged bool,
) (change.Change, error) {
	// Hostinfo changes require NodeAdded (full update) as they may affect many fields.
	if hostinfoChanged {
		return change.NodeAdded(id), nil
	}

	// Return specific change types for endpoint and/or DERP updates.
	if endpointChanged || derpChanged {
		patch := &tailcfg.PeerChange{NodeID: id.NodeID()}

		if endpointChanged {
			patch.Endpoints = node.Endpoints().AsSlice()
		}

		if derpChanged {
			if hi := node.Hostinfo(); hi.Valid() {
				if ni := hi.NetInfo(); ni.Valid() {
					patch.DERPRegion = ni.PreferredDERP()
				}
			}
		}

		return change.EndpointOrDERPUpdate(id, patch), nil
	}

	return change.NodeAdded(id), nil
}

func hostinfoEqual(oldNode types.NodeView, newHI *tailcfg.Hostinfo) bool {
	if !oldNode.Valid() && newHI == nil {
		return true
	}

	if !oldNode.Valid() || newHI == nil {
		return false
	}

	old := oldNode.AsStruct().Hostinfo

	return old.Equal(newHI)
}

func routesChanged(oldNode types.NodeView, newHI *tailcfg.Hostinfo) bool {
	var oldRoutes []netip.Prefix
	if oldNode.Valid() && oldNode.AsStruct().Hostinfo != nil {
		oldRoutes = oldNode.AsStruct().Hostinfo.RoutableIPs
	}

	newRoutes := newHI.RoutableIPs
	if newRoutes == nil {
		newRoutes = []netip.Prefix{}
	}

	tsaddr.SortPrefixes(oldRoutes)
	tsaddr.SortPrefixes(newRoutes)

	return !slices.Equal(oldRoutes, newRoutes)
}

func peerChangeEmpty(peerChange tailcfg.PeerChange) bool {
	return peerChange.Key == nil &&
		peerChange.DiscoKey == nil &&
		peerChange.Online == nil &&
		peerChange.Endpoints == nil &&
		peerChange.DERPRegion == 0 &&
		peerChange.LastSeen == nil &&
		peerChange.KeyExpiry == nil
}

// maybeUpdateNodeRoutes updates node routes if announced routes changed but approved routes didn't.
// This is needed because SubnetRoutes is the intersection of announced AND approved routes.
func (s *State) maybeUpdateNodeRoutes(
	id types.NodeID,
	node types.NodeView,
	hostinfoChanged, needsRouteApproval, routeChange bool,
	hostinfo *tailcfg.Hostinfo,
) change.Change {
	// Only update if announced routes changed without approval change
	if !hostinfoChanged || !needsRouteApproval || routeChange || hostinfo == nil {
		return change.Change{}
	}

	log.Debug().
		Caller().
		Uint64("node.id", id.Uint64()).
		Msg("updating routes because announced routes changed but approved routes did not")

	// SetNodeRoutes sets the active/distributed routes using AllApprovedRoutes()
	// which returns only the intersection of announced AND approved routes.
	log.Debug().
		Caller().
		Uint64("node.id", id.Uint64()).
		Strs("announcedRoutes", util.PrefixesToString(node.AnnouncedRoutes())).
		Strs("approvedRoutes", util.PrefixesToString(node.ApprovedRoutes().AsSlice())).
		Strs("allApprovedRoutes", util.PrefixesToString(node.AllApprovedRoutes())).
		Msg("updating node routes for distribution")

	return s.SetNodeRoutes(id, node.AllApprovedRoutes()...)
}
