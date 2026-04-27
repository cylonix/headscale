package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"zgo.at/zcache/v2" // __CYLONIX_ADD__ supplants patrickmn/go-cache used pre-v0.28
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg" // __CYLONIX_ADD__
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

const (
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2
)

var invalidDNSRegex = regexp.MustCompile("[^a-z0-9-.]+")

var (
	ErrNodeNotFound                  = errors.New("node not found")
	ErrNodeRouteIsNotAvailable       = errors.New("route is not available on node")
	ErrNodeNotFoundRegistrationCache = errors.New(
		"node not found in registration cache",
	)
	ErrCouldNotConvertNodeInterface = errors.New("failed to convert node interface")
	// __BEGIN_CYLONIX_ADD__
	ErrDifferentRegisteredUser = errors.New(
		"node was previously registered with a different user",
	)
	// __END_CYLONIX_ADD__
)

// ListPeers returns peers of node, regardless of any Policy or if the node is expired.
// If no peer IDs are given, all peers are returned.
// If at least one peer ID is given, only these peer nodes will be returned.
func (hsdb *HSDatabase) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	return ListPeers(hsdb.DB, nodeID, peerIDs...)
}

// ListPeers returns peers of node, regardless of any Policy or if the node is expired.
// If no peer IDs are given, all peers are returned.
// If at least one peer ID is given, only these peer nodes will be returned.
func ListPeers(tx *gorm.DB, nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Capabilities"). // __CYLONIX_ADD__
		Where("id <> ?", nodeID).
		Where(peerIDs).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return nodes, nil
}

// ListNodes queries the database for either all nodes if no parameters are given
// or for the given nodes if at least one node ID is given as parameter.
func (hsdb *HSDatabase) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	return ListNodes(hsdb.DB, nodeIDs...)
}

// ListNodes queries the database for either all nodes if no parameters are given
// or for the given nodes if at least one node ID is given as parameter.
func ListNodes(tx *gorm.DB, nodeIDs ...types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Capabilities").    // __CYLONIX_ADD__
		Preload("WouldShareTo").    // __CYLONIX_ADD__
		Preload("AcceptedShareTo"). // __CYLONIX_ADD__
		Where(nodeIDs).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

// __BEGIN_CYLONIX_ADD__
// listNodes returns []*types.Node (instead of types.Nodes) so that it can be
// used directly by the generic ListWithOptions helper.
func listNodes(tx *gorm.DB) ([]*types.Node, error) {
	nodes := []*types.Node{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Capabilities").
		Preload("WouldShareTo").
		Preload("AcceptedShareTo").
		Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func (hsdb *HSDatabase) ListNodesByIDList(idList []types.NodeID) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		rx = rx.Model(&types.Node{}).Where("id in ?", idList)
		return ListNodes(rx)
	})
}

func (hsdb *HSDatabase) ListNodesWithOptions(
	idList []uint64, namespace *string, network, username string,
	onlineOnly, namespaceLike, shareInOnly bool, onlineIDs []uint64,
	filterBy, filterValue, sortBy, sortDesc string,
	page, pageSize int,
) (int, types.Nodes, error) {
	var total int64
	n := "nil"
	if namespace != nil {
		n = *namespace
	}
	log.Trace().
		Str("namespace", n).
		Str("network", network).
		Str("username", username).
		Str("filterBy", filterBy).
		Str("filterValue", filterValue).
		Bool("shareInOnly", shareInOnly).
		Str("sortBy", sortBy).
		Str("sortDesc", sortDesc).
		Msg("Listing nodes with options")
	nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		var nodes types.Nodes
		var count int64
		var err error

		if shareInOnly {
			if username != "" {
				user := &types.User{}
				err := rx.Model(&types.User{}).First(user, "name = ?", username).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						return types.Nodes{}, nil
					}
					return types.Nodes{}, err
				}
				rx = rx.Model(&types.Node{})
				rx = rx.Joins("JOIN node_accepted_share_to_users_relation ON nodes.id = node_accepted_share_to_users_relation.node_id")
				rx = rx.Where("node_accepted_share_to_users_relation.user_id = ?", user.ID)
				network = ""
				username = ""
			} else {
				rx = rx.Model(&types.Node{})
				rx = rx.Where("EXISTS (SELECT 1 FROM node_accepted_share_to_users_relation WHERE node_accepted_share_to_users_relation.node_id = nodes.id)")
			}
		}
		ptrNodes, count, err := ListWithOptions(
			&types.Node{}, rx, listNodes,
			idList, namespace, "network_domain", network, username,
			onlineOnly, namespaceLike, "nodes", onlineIDs,
			nil,
			filterBy, filterValue, sortBy, sortDesc, page, pageSize,
		)
		for _, n := range ptrNodes {
			nodes = append(nodes, n)
		}
		log.Trace().
			Str("network", network).
			Str("username", username).
			Int("count", int(count)).
			Msg("Listed nodes with options")
		total = count
		return nodes, err
	})
	return int(total), nodes, err
}

// __END_CYLONIX_ADD__

func (hsdb *HSDatabase) ListEphemeralNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		nodes := types.Nodes{}
		if err := rx.Joins("AuthKey").Where(`"AuthKey"."ephemeral" = true`).Find(&nodes).Error; err != nil {
			return nil, err
		}

		return nodes, nil
	})
}

// __BEGIN_CYLONIX_ADD__
// listNodesByGivenName resolves nodes sharing a GivenName within a single
// cylonix network_domain (the GivenName unique index is per-network_domain).
func listNodesByGivenName(tx *gorm.DB, givenName, networkDomain string) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Where("given_name = ? and network_domain = ?", givenName, networkDomain).
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

// __END_CYLONIX_ADD__

func (hsdb *HSDatabase) getNode(uid types.UserID, name string) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return getNode(rx, uid, name)
	})
}

// getNode finds a Node by name and user and returns the Node struct.
func getNode(tx *gorm.DB, uid types.UserID, name string) (*types.Node, error) {
	nodes, err := ListNodesByUser(tx, uid)
	if err != nil {
		return nil, err
	}

	for _, m := range nodes {
		if m.Hostname == name {
			return m, nil
		}
	}

	return nil, ErrNodeNotFound
}

func (hsdb *HSDatabase) GetNodeByID(id types.NodeID) (*types.Node, error) {
	return GetNodeByID(hsdb.DB, id)
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func GetNodeByID(tx *gorm.DB, id types.NodeID) (*types.Node, error) {
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Capabilities").    // __CYLONIX_ADD__
		Preload("WouldShareTo").    // __CYLONIX_ADD__
		Preload("AcceptedShareTo"). // __CYLONIX_ADD__
		Find(&types.Node{ID: id}).First(&mach); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, result.Error
	}

	return &mach, nil
}

// GetNodeByMachineKey finds a Node by its username and machineky.
// Cylonix scopes machine keys per-user because the same physical device may be
// registered across different tenants as separate headscale users.
func (hsdb *HSDatabase) GetNodeByMachineKey(username string, machineKey key.MachinePublic) (*types.Node, error) { // __CYLONIX_MOD__
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByMachineKey(rx, username, machineKey) // __CYLONIX_MOD__
	})
}

func GetNodeByMachineKey(
	tx *gorm.DB,
	username string, // __CYLONIX_ADD__
	machineKey key.MachinePublic,
) (*types.Node, error) {
	// __BEGIN_CYLONIX_ADD__
	user, err := GetUser(tx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user '%v': %w", username, err)
	}
	// __END_CYLONIX_ADD__
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		First(&mach, "user_id = ? AND machine_key = ?", user.ID, machineKey.String()); result.Error != nil { // __CYLONIX_MOD__
		return nil, result.Error
	}

	return &mach, nil
}

// __BEGIN_CYLONIX_ADD__

// GetNodeByUserAndMachineKey finds a Node by user ID and machine key.
// Used for scoped lookups during auth/registration when the user is known.
// These are stable identifiers that survive node key rotation.
func (hsdb *HSDatabase) GetNodeByUserAndMachineKey(
	userID uint,
	machineKey key.MachinePublic,
) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByUserAndMachineKey(rx, userID, machineKey)
	})
}

func GetNodeByUserAndMachineKey(
	tx *gorm.DB,
	userID uint,
	machineKey key.MachinePublic,
) (*types.Node, error) {
	node := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		First(&node, "user_id = ? AND machine_key = ?", userID, machineKey.String()); result.Error != nil {
		return nil, result.Error
	}
	return &node, nil
}

// __END_CYLONIX_ADD__

// GetNodeByNodeKey finds a Node by its current node key.
// Used for global lookups when no user context is available (noise handlers, health, caps).
// NodeKey is globally unique.
func (hsdb *HSDatabase) GetNodeByNodeKey(
	nodeKey key.NodePublic,
) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByNodeKey(rx, nodeKey)
	})
}

func GetNodeByNodeKey(
	tx *gorm.DB,
	nodeKey key.NodePublic,
) (*types.Node, error) {
	node := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		First(&node, "node_key = ?", nodeKey.String()); result.Error != nil {
		return nil, result.Error
	}
	return &node, nil
}

// GetNodeByNodeKeyLite finds a Node by its current node key without preloads.
// Used for lightweight lookups where only node fields are needed (health, caps).
func (hsdb *HSDatabase) GetNodeByNodeKeyLite(
	nodeKey key.NodePublic,
) (*types.Node, error) {
	node := types.Node{}
	if result := hsdb.DB.
		First(&node, "node_key = ?", nodeKey.String()); result.Error != nil {
		return nil, result.Error
	}
	return &node, nil
}

// __END_CYLONIX_MOD__

func (hsdb *HSDatabase) SetTags(
	nodeID types.NodeID,
	tags []string,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetTags(tx, nodeID, tags)
	})
}

// SetTags takes a NodeID and update the forced tags.
// It will overwrite any tags with the new list.
func SetTags(
	tx *gorm.DB,
	nodeID types.NodeID,
	tags []string,
) error {
	if len(tags) == 0 {
		// if no tags are provided, we remove all tags
		err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("tags", "[]").Error
		if err != nil {
			return fmt.Errorf("removing tags: %w", err)
		}

		return nil
	}

	slices.Sort(tags)
	tags = slices.Compact(tags)
	b, err := json.Marshal(tags)
	if err != nil {
		return err
	}

	err = tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("tags", string(b)).Error
	if err != nil {
		return fmt.Errorf("updating tags: %w", err)
	}

	return nil
}

// SetTags takes a Node struct pointer and update the forced tags.
func SetApprovedRoutes(
	tx *gorm.DB,
	nodeID types.NodeID,
	routes []netip.Prefix,
) error {
	if len(routes) == 0 {
		// if no routes are provided, we remove all
		if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", "[]").Error; err != nil {
			return fmt.Errorf("removing approved routes: %w", err)
		}

		return nil
	}

	// When approving exit routes, ensure both IPv4 and IPv6 are included
	// If either 0.0.0.0/0 or ::/0 is being approved, both should be approved
	hasIPv4Exit := slices.Contains(routes, tsaddr.AllIPv4())
	hasIPv6Exit := slices.Contains(routes, tsaddr.AllIPv6())

	if hasIPv4Exit && !hasIPv6Exit {
		routes = append(routes, tsaddr.AllIPv6())
	} else if hasIPv6Exit && !hasIPv4Exit {
		routes = append(routes, tsaddr.AllIPv4())
	}

	b, err := json.Marshal(routes)
	if err != nil {
		return err
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", string(b)).Error; err != nil {
		return fmt.Errorf("updating approved routes: %w", err)
	}

	return nil
}

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func (hsdb *HSDatabase) SetLastSeen(nodeID types.NodeID, lastSeen time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetLastSeen(tx, nodeID, lastSeen)
	})
}

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func SetLastSeen(tx *gorm.DB, nodeID types.NodeID, lastSeen time.Time) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("last_seen", lastSeen).Error
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it. Validation should be done in the state layer before calling this function.
func RenameNode(tx *gorm.DB,
	nodeID types.NodeID, newName string,
) error {
	if err := util.ValidateHostname(newName); err != nil {
		return fmt.Errorf("renaming node: %w", err)
	}

	// Check if the new name is unique
	var count int64
	if err := tx.Model(&types.Node{}).Where("given_name = ? AND id != ?", newName, nodeID).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check name uniqueness: %w", err)
	}

	if count > 0 {
		return errors.New("name is not unique")
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("given_name", newName).Error; err != nil {
		return fmt.Errorf("failed to rename node in the database: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) NodeSetExpiry(nodeID types.NodeID, expiry time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return NodeSetExpiry(tx, nodeID, expiry)
	})
}

// NodeSetExpiry takes a Node struct and  a new expiry time.
func NodeSetExpiry(tx *gorm.DB,
	nodeID types.NodeID, expiry time.Time,
) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("expiry", expiry).Error
}

func (hsdb *HSDatabase) DeleteNode(node *types.Node) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteNode(tx, node)
	})
}

// __BEGIN_CYLONIX_ADD__
// DeleteNodeWithHandler deletes a node and then invokes the supplied cylonix
// NodeHandler so the daemon can remove WG / firewall / IPDrawer bindings in
// the same unit of work. Upstream's DeleteNode no longer takes a handler since
// routes are denormalised onto the node itself.
func (hsdb *HSDatabase) DeleteNodeWithHandler(node *types.Node, nodeHandler types.NodeHandler) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		if nodeHandler != nil {
			if err := nodeHandler.Delete(node); err != nil {
				return err
			}
		}
		return DeleteNode(tx, node)
	})
}

// __END_CYLONIX_ADD__

// DeleteNode deletes a Node from the database.
// Caller is responsible for notifying all of change.
func DeleteNode(tx *gorm.DB,
	node *types.Node,
) error {
	// Unscoped causes the node to be fully removed from the database.
	if err := tx.Unscoped().Delete(&types.Node{}, node.ID).Error; err != nil {
		return err
	}

	return nil
}

// DeleteEphemeralNode deletes a Node from the database, note that this method
// will remove it straight, and not notify any changes or consider any routes.
// It is intended for Ephemeral nodes.
func (hsdb *HSDatabase) DeleteEphemeralNode(
	nodeID types.NodeID,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Delete(&types.Node{}, nodeID).Error; err != nil {
			return err
		}
		return nil
	})
}

// __BEGIN_CYLONIX_ADD__
// RegisterNodeFromAuthCallback is the cylonix-specific registration entry
// point invoked after an external auth provider (OIDC / SSO) confirms the
// user. Upstream moved this logic into state.HandleNodeFromAuthPath, but
// cylonix still dispatches through the db layer so the NodeHandler can stamp
// namespace + network_domain atomically with the row insert.
func RegisterNodeFromAuthCallback(
	tx *gorm.DB,
	regCache *zcache.Cache[types.RegistrationID, types.RegisterNode],
	registrationID types.RegistrationID,
	userName string,
	nodeExpiry *time.Time,
	registrationMethod string,
	ipv4 *netip.Addr,
	ipv6 *netip.Addr,
	nodeHandler types.NodeHandler,
) (*types.Node, error) {
	registration, ok := regCache.Get(registrationID)
	if !ok {
		return nil, ErrNodeNotFoundRegistrationCache
	}
	registrationNode := registration.Node
	mkey := registrationNode.MachineKey

	log.Debug().
		Str("machine_key", mkey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", nodeExpiry)).
		Msg("Registering node from API/CLI or auth callback")
	user, err := GetUser(tx, userName)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find user in register node from auth callback, %w",
			err,
		)
	}

	// Registration of expired node with different user.
	if registrationNode.ID != 0 &&
		registrationNode.UserID != nil && *registrationNode.UserID != user.ID {
		return nil, ErrDifferentRegisteredUser
	}

	// Cache has been hit with the callback. Delete it before it
	// can be re-used even for error since the provider of the auth
	// URL may have set the state to be authorized already.
	log.Info().
		Caller().
		Str("machine_key", mkey.ShortString()).
		Str("node_key", registrationNode.NodeKey.ShortString()).
		Msg("Cache hit with auth callback, deleting cache entry")
	regCache.Delete(registrationID)

	node, err := GetNodeByUserAndMachineKey(tx, user.ID, mkey)
	if !registrationNode.NodeKey.IsZero() {
		nodeByKey, _ := GetNodeByNodeKey(tx, registrationNode.NodeKey)
		if nodeByKey != nil {
			if node != nil && nodeByKey.ID != node.ID {
				return nil, fmt.Errorf("node key conflict: nodeKey belongs to different node")
			}
			if node == nil && (nodeByKey.UserID == nil || *nodeByKey.UserID != user.ID) {
				return nil, fmt.Errorf("node key conflict: nodeKey belongs to different user")
			}
			if node == nil {
				node = nodeByKey
				err = nil
			}
		}
	}
	if err == nil {
		node.NodeKey = registrationNode.NodeKey
		registrationNode.RegisterMethod = registrationMethod
		if nodeExpiry != nil {
			node.Expiry = nodeExpiry
		}
		if nodeHandler != nil && node.User != nil {
			networkDomain, err := nodeHandler.NetworkDomain(node.User)
			if err != nil {
				return nil, fmt.Errorf("failed to get network domain: %w", err)
			}
			if node.NetworkDomain != string(networkDomain) {
				oldDomain := node.NetworkDomain
				node.NetworkDomain = string(networkDomain)
				log.Info().
					Str("node", node.Hostname).
					Str("old-network-domain", oldDomain).
					Str("new-network-domain", string(networkDomain)).
					Msg("Updated network domain for node")
			}
		}
		v, _ := json.Marshal(node.Hostinfo)
		node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
		if err := tx.Save(node).Error; err != nil {
			return nil, fmt.Errorf("failed to update node key for %v of %v in the database: %w", node.Hostname, userName, err)
		}
		return node, nil
	}

	registrationNode.UserID = &user.ID
	registrationNode.User = user
	registrationNode.RegisterMethod = registrationMethod

	if nodeExpiry != nil {
		registrationNode.Expiry = nodeExpiry
	}

	return RegisterNode(
		tx,
		registrationNode,
		ipv4, ipv6,
		nodeHandler,
	)
}

// __END_CYLONIX_ADD__

func (hsdb *HSDatabase) RegisterNode(node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr, nodeHandler types.NodeHandler) (*types.Node, error) { // __CYLONIX_MOD__
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Node, error) {
		return RegisterNode(tx, node, ipv4, ipv6, nodeHandler) // __CYLONIX_MOD__
	})
}

// RegisterNode is executed from the CLI to register a new Node using its
// MachineKey. Cylonix extends the upstream signature with a NodeHandler so
// the caller (daemon) can participate in the create transaction (stamp
// network_domain, notify WG, etc.).
func RegisterNode(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr, nodeHandler types.NodeHandler) (*types.Node, error) { // __CYLONIX_MOD__
	// __BEGIN_CYLONIX_MOD__
	logEvent := log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey.ShortString()).
		Str("node_key", node.NodeKey.ShortString())
	if node.User != nil {
		logEvent = logEvent.
			Str("user", node.User.Name).
			Str("Namespace", node.User.GetNamespace())
	}
	logEvent.Msg("Registering node")
	// __END_CYLONIX_MOD__

	// If the node exists and it already has IP(s), we just save it
	// so we store the node.Expire and node.Nodekey that has been set when
	// adding it to the registrationCache
	if node.IPv4 != nil || node.IPv6 != nil {
		// __BEGIN_CYLONIX_MOD__
		if err := RegisterNodePreAdd(tx, &node, nodeHandler); err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}
		v, _ := json.Marshal(node.Hostinfo)
		node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
		// __END_CYLONIX_MOD__
		if err := tx.Save(&node).Error; err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}

		traceEvent := log.Trace().
			Caller().
			Str("node", node.Hostname).
			Str("machine_key", node.MachineKey.ShortString()).
			Str("node_key", node.NodeKey.ShortString())
		if node.User != nil {
			traceEvent = traceEvent.Str("user", node.User.Username())
		}
		traceEvent.Msg("Node authorized again") // __CYLONIX_MOD__

		// __BEGIN_CYLONIX_MOD__
		if nodeHandler != nil {
			if err := nodeHandler.PostAdd(&node); err != nil {
				return nil, err
			}
		}
		// __END_CYLONIX_MOD__

		return &node, nil
	}

	node.IPv4 = ipv4
	node.IPv6 = ipv6

	// __BEGIN_CYLONIX_MOD__
	// Normalise hostname first so the cylonix pre-add (which derives
	// given_name) sees the sanitized value. Upstream's EnsureUniqueGivenName
	// is the simple global-uniqueness helper; cylonix replaces it with the
	// per-network-domain GenerateGivenName flow executed inside
	// RegisterNodePreAdd via the NodeHandler.
	normalisedHostname, err := util.NormaliseHostname(node.Hostname)
	if err != nil {
		newHostname := util.InvalidString()
		log.Info().Err(err).
			Str("invalid-hostname", node.Hostname).
			Str("new-hostname", newHostname).
			Msgf("Invalid hostname, replacing")
		node.Hostname = newHostname
	} else {
		node.Hostname = normalisedHostname
	}
	if err := RegisterNodePreAdd(tx, &node, nodeHandler); err != nil {
		return nil, fmt.Errorf("failed register(pre-add) node in the database: %w", err)
	}
	if node.User != nil {
		node.Namespace = node.User.GetNamespace()
	}
	if node.GivenName == "" {
		givenName, err := EnsureUniqueGivenName(tx, node.Hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure unique given name: %w", err)
		}
		node.GivenName = givenName
	}
	v, _ := json.Marshal(node.Hostinfo)
	node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
	// __END_CYLONIX_MOD__

	if err := tx.Save(&node).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) node in the database: %w", err)
	}

	// __BEGIN_CYLONIX_MOD__
	if nodeHandler != nil {
		if err := nodeHandler.PostAdd(&node); err != nil {
			return nil, err
		}
	}
	// __END_CYLONIX_MOD__

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msg("Node registered with the database") // __CYLONIX_MOD__

	return &node, nil
}

// __BEGIN_CYLONIX_ADD__
// RegisterNodeForTest is used only for testing purposes to register a node
// directly in the database. Production code should go through RegisterNode /
// RegisterNodeFromAuthCallback so NodeHandler side effects run. This wrapper
// mirrors upstream's v0.28 helper signature so upstream tests still compile.
func RegisterNodeForTest(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr) (*types.Node, error) {
	if !testing.Testing() {
		panic("RegisterNodeForTest can only be called during tests")
	}
	return RegisterNode(tx, node, ipv4, ipv6, nil)
}

// __END_CYLONIX_ADD__

// NodeSetNodeKey sets the node key of a node and saves it to the database.
func NodeSetNodeKey(tx *gorm.DB, node *types.Node, nodeKey key.NodePublic) error {
	node.NodeKey = nodeKey // __CYLONIX_ADD__ keep in-memory copy aligned with DB
	return tx.Model(node).Updates(types.Node{
		NodeKey: nodeKey,
	}).Error
}

func (hsdb *HSDatabase) NodeSetMachineKey(
	node *types.Node,
	machineKey key.MachinePublic,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return NodeSetMachineKey(tx, node, machineKey)
	})
}

// NodeSetMachineKey sets the node key of a node and saves it to the database.
func NodeSetMachineKey(
	tx *gorm.DB,
	node *types.Node,
	machineKey key.MachinePublic,
) error {
	node.MachineKey = machineKey // __CYLONIX_ADD__ keep in-memory copy aligned with DB
	return tx.Model(node).Updates(types.Node{
		MachineKey: machineKey,
	}).Error
}

// __BEGIN_CYLONIX_ADD__
// NodeSave saves a node object to the database, prefer to use a specific save
// method rather than this. Kept from the cylonix fork because the daemon has a
// handful of call sites that need to persist a mixed-field update without
// having to enumerate which columns changed.
// TODO(kradalby): Remove this func, just use Save.
func NodeSave(tx *gorm.DB, node *types.Node) error {
	v, _ := json.Marshal(node.Hostinfo)
	node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
	return tx.Save(node).Error
}

// __END_CYLONIX_ADD__

// NOTE: The previous cylonix GetAdvertisedRoutes/GetEnabledRoutes/IsRoutesEnabled/enableRoutes
// helpers were removed in the merge to upstream v0.28.0 because the Route
// table was dropped in favour of Node.ApprovedRoutes ([]netip.Prefix) stored
// directly on the node row. Callers should read node.ApprovedRoutes (or
// node.AnnouncedRoutes via Hostinfo) instead.

func generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	// Strip invalid DNS characters for givenName
	suppliedName = strings.ToLower(suppliedName)
	suppliedName = invalidDNSRegex.ReplaceAllString(suppliedName, "")
	suppliedName = strings.ReplaceAll(suppliedName, ".", "-") // Don't allow '.' in hostname __CYLONIX_MOD__

	if len(suppliedName) > util.LabelHostnameLength {
		return "", types.ErrHostnameTooLong
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := util.LabelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(suppliedName) > trimmedHostnameLength {
			suppliedName = suppliedName[:trimmedHostnameLength]
		}

		suffix, err := util.GenerateRandomStringDNSSafe(NodeGivenNameHashLength)
		if err != nil {
			return "", err
		}

		suppliedName += "-" + suffix
	}

	return suppliedName, nil
}

// __BEGIN_CYLONIX_ADD__
func (hsdb *HSDatabase) GenerateGivenName(
	mkey key.MachinePublic,
	suppliedName string,
	networkDomain string, nodeID *types.NodeID, currentGivenName *string,
) (string, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (string, error) {
		return GenerateGivenName(rx, mkey, suppliedName, networkDomain, nodeID, currentGivenName)
	})
}

var givenNamePattern = regexp.MustCompile(`^(.+?)(?:-([1-9][0-9]?|1[0-2][0-8])?)?$`)

// GenerateGivenName is the cylonix per-network-domain unique-name allocator.
// It differs from upstream EnsureUniqueGivenName in three ways:
//  1. Uniqueness is scoped to networkDomain, not global.
//  2. If the supplied name is already taken the numeric suffix is found via
//     binary search between -1 and -128 before falling back to a random hash.
//  3. If the caller passes currentGivenName that already matches either the
//     base name or the base-[digit] pattern we keep it to avoid churning the
//     DNS record for a rename-that-isn't.
func GenerateGivenName(
	tx *gorm.DB,
	mkey key.MachinePublic,
	suppliedName string,
	networkDomain string,
	nodeID *types.NodeID,
	currentGivenName *string,
) (string, error) {
	givenName, err := generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	// If the current given name is already the same as the generated one or
	// has the same prefix before the -[digit], we can return it.
	if currentGivenName != nil {
		if *currentGivenName == givenName {
			return *currentGivenName, nil
		}

		// Check if currentGivenName matches givenName-X where X is 1-128
		matches := givenNamePattern.FindStringSubmatch(*currentGivenName)
		if len(matches) == 3 && matches[1] == givenName {
			if matches[2] != "" { // Has numeric suffix
				return *currentGivenName, nil
			}
		}
	}
	// Try with 1-128 with binary search before going with a random suffix.
	// First check if base name is available
	nodes, err := listNodesByGivenName(tx, givenName, networkDomain)
	if err != nil {
		return "", err
	}
	if len(nodes) == 0 {
		return givenName, nil
	}
	if len(nodes) != 1 {
		return "", fmt.Errorf("multiple nodes with the same given name %s found in the database, this should not happen", givenName)
	}
	if nodeID != nil && nodes[0].ID == *nodeID {
		// If the node is the same as the one we are updating, we can use the given name.
		return givenName, nil
	}

	// Binary search to find first available index
	left, right := 1, 128
	for left <= right {
		mid := (left + right) / 2
		testName := fmt.Sprintf("%s-%d", givenName, mid)
		nodes, err := listNodesByGivenName(tx, testName, networkDomain)
		if err != nil {
			return "", err
		}

		if len(nodes) == 0 {
			// Found an available slot, try to find a lower one
			right = mid - 1
		} else {
			if len(nodes) != 1 {
				return "", fmt.Errorf("multiple nodes with the same given name %s found in the database, this should not happen", testName)
			}
			if nodeID != nil && nodes[0].ID == *nodeID {
				// If the node is the same as the one we are updating, we can use the given name.
				return testName, nil
			}
			// Slot taken, try higher numbers
			left = mid + 1
		}
	}

	// left now contains the first available index
	if left <= 128 {
		return fmt.Sprintf("%s-%d", givenName, left), nil
	}

	// If all slots are taken, generate a random suffix
	return generateGivenName(suppliedName, true)
}

// __END_CYLONIX_ADD__

func isUniqueName(tx *gorm.DB, name string) (bool, error) {
	nodes := types.Nodes{}
	if err := tx.
		Where("given_name = ?", name).Find(&nodes).Error; err != nil {
		return false, err
	}

	return len(nodes) == 0, nil
}

// EnsureUniqueGivenName generates a unique given name for a node based on its hostname.
// This is the upstream helper; cylonix prefers GenerateGivenName (above) for
// production call sites that know the network_domain. Keep EnsureUniqueGivenName
// as a fallback so upstream tests and the RegisterNode test path keep working.
func EnsureUniqueGivenName(
	tx *gorm.DB,
	name string,
) (string, error) {
	givenName, err := generateGivenName(name, false)
	if err != nil {
		return "", err
	}

	unique, err := isUniqueName(tx, givenName)
	if err != nil {
		return "", err
	}

	if !unique {
		postfixedName, err := generateGivenName(name, true)
		if err != nil {
			return "", err
		}

		givenName = postfixedName
	}

	return givenName, nil
}

// __BEGIN_CYLONIX_ADD__
// ExpireExpiredNodes iterates all nodes, finds any whose expiry crossed
// lastCheck, and returns a StatePeerChangedPatch update for them. Upstream
// deleted this in v0.26 in favour of a NodeStore-driven expiry loop; cylonix
// still drives expiry from the db layer through the tenant scheduler.
// TODO: (randy) Make this per network domain or namespace.
func ExpireExpiredNodes(tx *gorm.DB,
	lastCheck time.Time,
) (time.Time, types.StateUpdate, bool) {
	// use the time of the start of the function to ensure we
	// dont miss some nodes by returning it _after_ we have
	// checked everything.
	started := time.Now()

	expired := make([]*tailcfg.PeerChange, 0)

	nodes, err := ListNodes(tx)
	if err != nil {
		return time.Unix(0, 0), types.StateUpdate{}, false
	}
	for _, node := range nodes {
		if node.IsExpired() && node.Expiry.After(lastCheck) {
			expired = append(expired, &tailcfg.PeerChange{
				NodeID:    tailcfg.NodeID(node.ID),
				KeyExpiry: node.Expiry,
			})
		}
	}

	if len(expired) > 0 {
		return started, types.StateUpdate{
			Type:          types.StatePeerChangedPatch,
			ChangePatches: expired,
		}, true
	}

	return started, types.StateUpdate{}, false
}

// __END_CYLONIX_ADD__


// EphemeralGarbageCollector is a garbage collector that will delete nodes after
// a certain amount of time.
// It is used to delete ephemeral nodes that have disconnected and should be
// cleaned up.
type EphemeralGarbageCollector struct {
	mu sync.Mutex

	deleteFunc  func(types.NodeID)
	toBeDeleted map[types.NodeID]*time.Timer

	deleteCh chan types.NodeID
	cancelCh chan struct{}
}

// NewEphemeralGarbageCollector creates a new EphemeralGarbageCollector, it takes
// a deleteFunc that will be called when a node is scheduled for deletion.
func NewEphemeralGarbageCollector(deleteFunc func(types.NodeID)) *EphemeralGarbageCollector {
	return &EphemeralGarbageCollector{
		toBeDeleted: make(map[types.NodeID]*time.Timer),
		deleteCh:    make(chan types.NodeID, 10),
		cancelCh:    make(chan struct{}),
		deleteFunc:  deleteFunc,
	}
}

// Close stops the garbage collector.
func (e *EphemeralGarbageCollector) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop all timers
	for _, timer := range e.toBeDeleted {
		timer.Stop()
	}

	// Close the cancel channel to signal all goroutines to exit
	close(e.cancelCh)
}

// Schedule schedules a node for deletion after the expiry duration.
// If the garbage collector is already closed, this is a no-op.
func (e *EphemeralGarbageCollector) Schedule(nodeID types.NodeID, expiry time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't schedule new timers if the garbage collector is already closed
	select {
	case <-e.cancelCh:
		// The cancel channel is closed, meaning the GC is shutting down
		// or already shut down, so we shouldn't schedule anything new
		return
	default:
		// Continue with scheduling
	}

	// If a timer already exists for this node, stop it first
	if oldTimer, exists := e.toBeDeleted[nodeID]; exists {
		oldTimer.Stop()
	}

	timer := time.NewTimer(expiry)
	e.toBeDeleted[nodeID] = timer
	// Start a goroutine to handle the timer completion
	go func() {
		select {
		case <-timer.C:
			// This is to handle the situation where the GC is shutting down and
			// we are trying to schedule a new node for deletion at the same time
			// i.e. We don't want to send to deleteCh if the GC is shutting down
			// So, we try to send to deleteCh, but also watch for cancelCh
			select {
			case e.deleteCh <- nodeID:
				// Successfully sent to deleteCh
			case <-e.cancelCh:
				// GC is shutting down, don't send to deleteCh
				return
			}
		case <-e.cancelCh:
			// If the GC is closed, exit the goroutine
			return
		}
	}()
}

// Cancel cancels the deletion of a node.
func (e *EphemeralGarbageCollector) Cancel(nodeID types.NodeID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if timer, ok := e.toBeDeleted[nodeID]; ok {
		timer.Stop()
		delete(e.toBeDeleted, nodeID)
	}
}

// Start starts the garbage collector.
func (e *EphemeralGarbageCollector) Start() {
	for {
		select {
		case <-e.cancelCh:
			return
		case nodeID := <-e.deleteCh:
			e.mu.Lock()
			delete(e.toBeDeleted, nodeID)
			e.mu.Unlock()

			go e.deleteFunc(nodeID)
		}
	}
}

// __BEGIN_CYLONIX_ADD__
func (hsdb *HSDatabase) UpdateNode(
	id types.NodeID,
	namespace string,
	update *types.Node,
	addCapabilities []string,
	delCapabilities []string,
) error {
	tx := hsdb.DB.Begin()
	defer tx.Rollback()

	node, err := GetNodeByID(tx, id)
	if err != nil {
		return err
	}

	// If the given name is being updated, we need to ensure it follows the rules
	// and generate a unique given name.
	if update.GivenName != "" && update.GivenName != node.GivenName {
		// util.CheckForFQDNRules was removed upstream; util.ValidateHostname
		// covers the same (label length, charset, reserved prefix) rules.
		if err := util.ValidateHostname(update.GivenName); err != nil {
			return fmt.Errorf("updating node given name: %w", err)
		}
		givenName, err := hsdb.GenerateGivenName(
			node.MachineKey, update.GivenName,
			node.NetworkDomain, &id, &node.GivenName,
		)
		if err != nil {
			return fmt.Errorf("generating unique given name: %w", err)
		}
		update.GivenName = givenName
	}

	// Preload the 'BeforeSave()' hook changed fields.
	node.PreloadUpdate(update)

	m := &types.Node{ID: id}
	update.ID = id
	tx = tx.Session(&gorm.Session{FullSaveAssociations: true})

	// NOTE: Previous cylonix versions of UpdateNode also reset the Routes
	// association when update.Routes was non-nil. Upstream v0.26 dropped the
	// separate Route table in favour of Node.ApprovedRoutes stored inline, so
	// the separate delete step is no longer needed.

	// Delete current associated capabilities if the 'Capabilities' field is
	// not 'nil'. Note for updates that do not intend to delete all the
	// capabilities, 'update.Capabilities' must be 'nil' instead of '[]'.
	// Typically request should use the specific 'addCapabilities' and
	// 'delCapabilities' parameters instead.
	if update.Capabilities != nil {
		if len(update.Capabilities) == 0 {
			log.Debug().
				Caller().
				Str("namespace", namespace).
				Uint64("node_id", uint64(node.ID)).
				Str("node", node.GivenName).
				Msg("Clearing capabilities with not-nil but empty capabilities field")
		}
		// ID fields need to be pre-populated for existing caps.
		if err := tx.Model(m).Association("Capabilities").Clear(); err != nil {
			return err
		}
		if err := addCapabilityIDs(tx, update.Capabilities); err != nil {
			return err
		}
	}
	if len(addCapabilities) > 0 {
		var add []string
		for _, c := range addCapabilities {
			found := false
			for _, nc := range node.Capabilities {
				if c == nc.Name {
					// Already has the capability, skip adding it again.
					log.Debug().
						Str("namespace", namespace).
						Uint64("node_id", uint64(node.ID)).
						Str("node", node.GivenName).
						Str("capability", c).
						Msg("Node already has capability, skipping adding it again")
					found = true
					break
				}
			}
			if !found {
				add = append(add, c)
			}
		}
		if len(add) > 0 {
			caps := types.ParseProtoCapabilities(namespace, add)
			if err := addCapabilityIDs(tx, caps); err != nil {
				return err
			}
			if err := tx.Model(m).
				Association("Capabilities").
				Append(caps); err != nil {
				return err
			}
		}
	}
	if len(delCapabilities) > 0 {
		var del []string
		for _, c := range delCapabilities {
			found := false
			for _, nc := range node.Capabilities {
				if c == nc.Name {
					// Has the capability, can be deleted.
					found = true
					break
				}
			}
			if found {
				del = append(del, c)
			}
		}
		if len(del) > 0 {
			caps := types.ParseProtoCapabilities(namespace, del)
			if err := addCapabilityIDs(tx, caps); err != nil {
				return err
			}
			if err := tx.Model(m).
				Association("Capabilities").
				Delete(caps); err != nil {
				return err
			}
		}
	}

	if err := tx.Updates(update).Error; err != nil {
		return err
	}

	nullableUpdates := make(map[string]interface{})

	// Check if we need to explicitly set any nullable fields to NULL

	// For updating online status to true and last_seen to NULL
	if update.LastSeen == nil && (update.IsOnline != nil && *update.IsOnline) {
		nullableUpdates["last_seen"] = nil
	}
	// Add other nullable pointer fields as needed...

	// Apply nullable field updates if any
	if len(nullableUpdates) > 0 {
		if err := tx.Model(&types.Node{}).
			Where("id = ?", id).
			Updates(nullableUpdates).Error; err != nil {
			return err
		}
	}

	return tx.Commit().Error
}

// To update capabilities, we need to make sure the ID field is pre-populated.
// Otherwise associations will fail as it only checks conflict on
// the id field with sql of: "...ON CONFLICT (`id`) DO UPDATE SET..."
func addCapabilityIDs(tx *gorm.DB, caps []types.Capability) error {
	if len(caps) <= 0 {
		return nil
	}

	capsNeedID := types.SliceFind(caps, func(c types.Capability) bool {
		return c.ID == 0
	})
	if len(capsNeedID) <= 0 {
		return nil
	}
	namespace := caps[0].Namespace
	capNames, _ := types.SliceMap(capsNeedID, func(c types.Capability) (string, error) {
		return c.Name, nil
	})
	var capsWithID []types.Capability
	if err := tx.
		Model(&types.Capability{}).
		Where("namespace = ? and name in ?", namespace, capNames).
		Find(&capsWithID).
		Error; err != nil {
		return err
	}
	if len(capsWithID) <= 0 {
		return nil
	}
	for i := range caps {
		c := &caps[i]
		for _, v := range capsWithID {
			if v.Name == c.Name {
				c.ID = v.ID
			}
		}
	}
	return nil
}

func RegisterNodePreAdd(tx *gorm.DB, node *types.Node, nodeHandler types.NodeHandler) error {
	if nodeHandler == nil {
		return nil
	}
	if _, err := nodeHandler.PreAdd(node); err != nil {
		return fmt.Errorf("failed register existing node in the database: %w", err)
	}
	// Regenerate the given name since we now have the node user information.
	if node.User == nil {
		return fmt.Errorf("RegisterNodePreAdd: node %s has no user", node.Hostname)
	}
	v, err := nodeHandler.NetworkDomain(node.User)
	if err != nil {
		return err
	}

	hostname := node.Hostinfo.Hostname
	if hostname == "localhost" || hostname == "" {
		hostname = node.Hostinfo.DeviceModel
	}

	networkDomain := string(v)
	givenName, err := GenerateGivenName(
		tx, node.MachineKey, hostname, networkDomain, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to generate given name: %w", err)
	}
	log.Info().
		Str("node", node.Hostname).
		Str("given_name", givenName).
		Str("network_domain", networkDomain).
		Msg("Generated given name for node") // __CYLONIX_MOD__

	node.GivenName = givenName
	node.NetworkDomain = networkDomain
	return nil
}

func (hsdb *HSDatabase) MaybeUpdateNodeGivenName(
	node *types.Node,
	hostinfo *tailcfg.Hostinfo,
) error {
	if hostinfo == nil || node.Hostname == hostinfo.Hostname {
		// No need to update the given name if the hostname is the same.
		return nil
	}
	newHostname := hostinfo.Hostname
	if newHostname == "localhost" || newHostname == "" {
		newHostname = hostinfo.DeviceModel
	}

	node.
		DebugLog().
		Str("new-hostname", newHostname).
		Str("given-name", node.GivenName).
		Msg("Updating given name for node")
	givenName, err := hsdb.GenerateGivenName(
		node.MachineKey, newHostname,
		node.NetworkDomain, &node.ID, &node.GivenName,
	)
	if err != nil {
		return err
	}
	node.Hostname = newHostname
	node.GivenName = givenName
	update := &types.Node{GivenName: givenName, Hostname: newHostname}
	if err := hsdb.UpdateNode(node.ID, node.Namespace, update, nil, nil); err != nil {
		return fmt.Errorf("failed to update node given name: %w", err)
	}
	node.DebugLog().Msgf("updated hostname to %s and given name to %s", newHostname, givenName)
	return nil
}

func (hsdb *HSDatabase) MaybeUpdateNodeCapVersion(
	node *types.Node,
	version uint32,
) error {
	if node.CapVersion != nil && *node.CapVersion == version {
		// No need to update the capability version if it's the same.
		return nil
	}

	currentVersion := uint32(0)
	if node.CapVersion != nil {
		currentVersion = *node.CapVersion
	}
	node.
		DebugLog().
		Uint32("new-cap-version", version).
		Uint32("current-cap-version", currentVersion).
		Msg("Updating capability version for node")
	node.CapVersion = &version
	update := &types.Node{CapVersion: &version}
	if err := hsdb.UpdateNode(node.ID, node.Namespace, update, nil, nil); err != nil {
		return fmt.Errorf("failed to update node capability version: %w", err)
	}
	return nil
}

type HealthChange struct {
	Subsys string
	Error  string
}

var (
	healthCacheMu sync.Mutex
	healthCache   = make(map[types.NodeID]string)
)

func (hsdb *HSDatabase) UpdateNodeHealth(
	node *types.Node,
	health *tailcfg.HealthChangeRequest,
) error {
	v, err := json.Marshal(&HealthChange{
		Subsys: health.Subsys,
		Error:  health.Error,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal health change: %w", err)
	}
	s := string(v)

	// Throttle: skip DB write if health status hasn't changed.
	healthCacheMu.Lock()
	if prev, ok := healthCache[node.ID]; ok && prev == s {
		healthCacheMu.Unlock()
		return nil
	}
	healthCache[node.ID] = s
	healthCacheMu.Unlock()

	tx := hsdb.DB.Begin()
	defer tx.Rollback()
	update := &types.Node{
		Health: &s,
	}
	node.PreloadUpdate(update)
	if err := tx.
		Model(&types.Node{}).
		Where("id = ?", node.ID).
		Updates(update).Error; err != nil {
		return fmt.Errorf("failed to update node health: %w", err)
	}
	log.Debug().
		Str("namespace", node.Namespace).
		Str("node", node.GivenName).
		Msg("Updated node health status")
	return tx.Commit().Error
}

func (hsdb *HSDatabase) ListWouldShareInNodes(user *types.User) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListWouldShareInNodes(rx, user)
	})
}

// ListWouldShareInNodes returns all nodes would like to share to the user,
// regardless of any policy or if the node is expired.
func ListWouldShareInNodes(tx *gorm.DB, user *types.User) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("User").
		Joins("JOIN node_would_share_to_users_relation ON nodes.id = node_would_share_to_users_relation.node_id").
		Where("nodes.namespace = ? AND node_would_share_to_users_relation.user_id = ?",
			user.Namespace,
			user.ID,
		).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}
	return nodes, nil
}

func (hsdb *HSDatabase) ListSharedInPeers(user *types.User) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListSharedInPeers(rx, user)
	})
}

// ListSharedInPeers returns all peers shared to this node, regardless of any
// Policy or if the node is expired. Shared in nodes are always considered
// jailed.
func ListSharedInPeers(tx *gorm.DB, user *types.User) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("User").
		Preload("Capabilities"). // Routes preload dropped: Route table removed upstream. __CYLONIX_MOD__
		Joins("JOIN node_accepted_share_to_users_relation ON nodes.id = node_accepted_share_to_users_relation.node_id").
		Where("nodes.namespace = ? AND node_accepted_share_to_users_relation.user_id = ?",
			user.Namespace,
			user.ID,
		).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	// Set these nodes to as jailed.
	for i := range nodes {
		nodes[i].IsJailed = true
	}
	return nodes, nil
}

func (hsdb *HSDatabase) ListSharedToPeers(node *types.Node) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListSharedToPeers(rx, node)
	})
}

// ListSharedToPeers returns all the peers this node has shared to, regardless
// of any policy or if the node is expired. Shared to nodes are always marked
// with ShareeNode in the host info.
func ListSharedToPeers(tx *gorm.DB, node *types.Node) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("User").
		Preload("Capabilities"). // Routes preload dropped: Route table removed upstream. __CYLONIX_MOD__
		Where("namespace = ? AND user_id IN (?)",
			node.Namespace,
			tx.Table("node_accepted_share_to_users_relation").
				Select("user_id").
				Where("node_id = ?", node.ID),
		).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	// Set these nodes to as sharee nodes.
	for i := range nodes {
		nodes[i].Hostinfo.ShareeNode = true
	}
	return nodes, nil
}

// AddWouldShareToUser adds a user to the node's WouldShareTo relationship.
func (hsdb *HSDatabase) AddWouldShareToUser(node *types.Node, user *types.User) error {
	return hsdb.DB.Model(node).Association("WouldShareTo").Append(user)
}

// RemoveWouldShareToUser removes a user from the node's WouldShareTo relationship.
func (hsdb *HSDatabase) RemoveWouldShareToUser(node *types.Node, user *types.User) error {
	// GORM's Association().Delete() doesn't return error if relation doesn't exist
	// It's idempotent and returns nil, which is the desired behavior
	return hsdb.DB.Model(node).Association("WouldShareTo").Delete(user)
}

// AddAcceptedShareToUser adds a user to the node's AcceptedShareTo relationship.
func (hsdb *HSDatabase) AddAcceptedShareToUser(node *types.Node, user *types.User) error {
	return hsdb.DB.Model(node).Association("AcceptedShareTo").Append(user)
}

// RemoveAcceptedShareToUser removes a user from the node's AcceptedShareTo relationship.
func (hsdb *HSDatabase) RemoveAcceptedShareToUser(node *types.Node, user *types.User) error {
	// GORM's Association().Delete() doesn't return error if relation doesn't exist
	// It's idempotent and returns nil, which is the desired behavior
	return hsdb.DB.Model(node).Association("AcceptedShareTo").Delete(user)
}

// __END_CYLONIX_ADD__

func (hsdb *HSDatabase) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	if !testing.Testing() {
		panic("CreateNodeForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateNodeForTest requires a valid user")
	}

	nodeName := "testnode"
	if len(hostname) > 0 && hostname[0] != "" {
		nodeName = hostname[0]
	}

	// Create a preauth key for the node
	pak, err := hsdb.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create preauth key for test node: %v", err))
	}

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	discoKey := key.NewDisco()

	node := &types.Node{
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		DiscoKey:       discoKey.Public(),
		Hostname:       nodeName,
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}

	err = hsdb.DB.Save(node).Error
	if err != nil {
		panic(fmt.Sprintf("failed to create test node: %v", err))
	}

	return node
}

func (hsdb *HSDatabase) CreateRegisteredNodeForTest(user *types.User, hostname ...string) *types.Node {
	if !testing.Testing() {
		panic("CreateRegisteredNodeForTest can only be called during tests")
	}

	node := hsdb.CreateNodeForTest(user, hostname...)

	// Allocate IPs for the test node using the database's IP allocator
	// This is a simplified allocation for testing - in production this would use State.ipAlloc
	ipv4, ipv6, err := hsdb.allocateTestIPs(node.ID)
	if err != nil {
		panic(fmt.Sprintf("failed to allocate IPs for test node: %v", err))
	}

	var registeredNode *types.Node
	err = hsdb.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		registeredNode, err = RegisterNodeForTest(tx, *node, ipv4, ipv6)
		return err
	})
	if err != nil {
		panic(fmt.Sprintf("failed to register test node: %v", err))
	}

	return registeredNode
}

func (hsdb *HSDatabase) CreateNodesForTest(user *types.User, count int, hostnamePrefix ...string) []*types.Node {
	if !testing.Testing() {
		panic("CreateNodesForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateNodesForTest requires a valid user")
	}

	prefix := "testnode"
	if len(hostnamePrefix) > 0 && hostnamePrefix[0] != "" {
		prefix = hostnamePrefix[0]
	}

	nodes := make([]*types.Node, count)
	for i := range count {
		hostname := prefix + "-" + strconv.Itoa(i)
		nodes[i] = hsdb.CreateNodeForTest(user, hostname)
	}

	return nodes
}

func (hsdb *HSDatabase) CreateRegisteredNodesForTest(user *types.User, count int, hostnamePrefix ...string) []*types.Node {
	if !testing.Testing() {
		panic("CreateRegisteredNodesForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateRegisteredNodesForTest requires a valid user")
	}

	prefix := "testnode"
	if len(hostnamePrefix) > 0 && hostnamePrefix[0] != "" {
		prefix = hostnamePrefix[0]
	}

	nodes := make([]*types.Node, count)
	for i := range count {
		hostname := prefix + "-" + strconv.Itoa(i)
		nodes[i] = hsdb.CreateRegisteredNodeForTest(user, hostname)
	}

	return nodes
}

// allocateTestIPs allocates sequential test IPs for nodes during testing.
func (hsdb *HSDatabase) allocateTestIPs(nodeID types.NodeID) (*netip.Addr, *netip.Addr, error) {
	if !testing.Testing() {
		panic("allocateTestIPs can only be called during tests")
	}

	// Use simple sequential allocation for tests
	// IPv4: 100.64.x.y (where x = nodeID/256, y = nodeID%256)
	// IPv6: fd7a:115c:a1e0::x:y (where x = high byte, y = low byte)
	// This supports up to 65535 nodes
	const (
		maxTestNodes    = 65535
		ipv4ByteDivisor = 256
	)

	if nodeID > maxTestNodes {
		return nil, nil, ErrCouldNotAllocateIP
	}

	// Split nodeID into high and low bytes for IPv4 (100.64.high.low)
	highByte := byte(nodeID / ipv4ByteDivisor)
	lowByte := byte(nodeID % ipv4ByteDivisor)
	ipv4 := netip.AddrFrom4([4]byte{100, 64, highByte, lowByte})

	// For IPv6, use the last two bytes of the address (fd7a:115c:a1e0::high:low)
	ipv6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, highByte, lowByte})

	return &ipv4, &ipv6, nil
}
