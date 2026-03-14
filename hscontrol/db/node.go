package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2
)

var (
	ErrNodeNotFound                  = errors.New("node not found")
	ErrNodeRouteIsNotAvailable       = errors.New("route is not available on node")
	ErrNodeNotFoundRegistrationCache = errors.New(
		"node not found in registration cache",
	)
	ErrCouldNotConvertNodeInterface = errors.New("failed to convert node interface")
	ErrDifferentRegisteredUser      = errors.New(
		"node was previously registered with a different user",
	)
)

func (hsdb *HSDatabase) ListPeers(nodeID types.NodeID) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListPeers(rx, nodeID)
	})
}

// ListPeers returns all peers of node, regardless of any Policy or if the node is expired.
func ListPeers(tx *gorm.DB, nodeID types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Preload("Capabilities"). // __CYLONIX_MOD__
		Where("id <> ?",
			nodeID).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return nodes, nil
}

func (hsdb *HSDatabase) ListNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListNodes(rx)
	})
}

// __BEGIN_CYLONIX_MOD__
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
			// Special handling for shareInOnly mode
			// This lists nodes that have AcceptedShareTo field matching criteria
			if username != "" {
				// Find nodes where the specified user is in AcceptedShareTo
				user := &types.User{}
				err := rx.Model(&types.User{}).First(user, "name = ?", username).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						return types.Nodes{}, nil
					}
					return types.Nodes{}, err
				}
				rx = rx.Model(&types.Node{})
				// Join with the many-to-many relation table
				rx = rx.Joins("JOIN node_accepted_share_to_users_relation ON nodes.id = node_accepted_share_to_users_relation.node_id")
				rx = rx.Where("node_accepted_share_to_users_relation.user_id = ?", user.ID)

				// Change the network and username to be not set as it could be
				// any network for the share-in nodes.
				network = ""
				username = ""
			} else {
				// Find nodes with non-empty AcceptedShareTo
				// for the current namespace or network
				rx = rx.Model(&types.Node{})
				rx = rx.Where("EXISTS (SELECT 1 FROM node_accepted_share_to_users_relation WHERE node_accepted_share_to_users_relation.node_id = nodes.id)")
			}
		}
		nodes, count, err = ListWithOptions(
			&types.Node{}, rx, listNodes,
			idList, namespace, "network_domain", network, username,
			onlineOnly, namespaceLike, "nodes", onlineIDs,
			nil,
			filterBy, filterValue, sortBy, sortDesc, page, pageSize,
		)
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

func ListNodes(tx *gorm.DB) (types.Nodes, error) {
	nodes, err := listNodes(tx)
	return types.Nodes(nodes), err
}
func listNodes(tx *gorm.DB) ([]*types.Node, error) {
	nodes := []*types.Node{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Preload("Capabilities").
		Preload("WouldShareTo").
		Preload("AcceptedShareTo").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

// __END_CYLONIX_MOD__

func (hsdb *HSDatabase) ListEphemeralNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		nodes := types.Nodes{}
		if err := rx.Joins("AuthKey").Where(`"AuthKey"."ephemeral" = true`).Find(&nodes).Error; err != nil {
			return nil, err
		}

		return nodes, nil
	})
}

func listNodesByGivenName(tx *gorm.DB, givenName, networkDomain string) (types.Nodes, error) { // __CYLONIX_MOD__
	nodes := types.Nodes{}
	if err := tx.
		Where("given_name = ? and network_domain = ?", givenName, networkDomain). // __CYLONIX_MOD__
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) getNode(user string, name string) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return getNode(rx, user, name)
	})
}

// getNode finds a Node by name and user and returns the Node struct.
func getNode(tx *gorm.DB, user string, name string) (*types.Node, error) {
	nodes, err := ListNodesByUser(tx, user)
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
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByID(rx, id)
	})
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func GetNodeByID(tx *gorm.DB, id types.NodeID) (*types.Node, error) {
	mach := types.Node{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Preload("Capabilities").    // __CYLONIX_ADD__
		Preload("WouldShareTo").    // __CYLONIX_ADD__
		Preload("AcceptedShareTo"). // __CYLONIX_ADD__
		Find(&types.Node{ID: id}).First(&mach).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrNodeNotFound
		}
		return nil, err
	}

	return &mach, nil
}

// GetNodeByUserAndName finds a Node by its username and machineky.
// We need to have the username since a machine can have multiple users.
func (hsdb *HSDatabase) GetNodeByMachineKey(username string, machineKey key.MachinePublic) (*types.Node, error) { // __CYLONIX_MOD__
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByMachineKey(rx, username, machineKey) // __CYLONIX_MOD__
	})
}

// GetNodeByUserAndName finds a Node by its username and machineky.
// We need to have the username since a machine can have multiple users.
func GetNodeByMachineKey(
	tx *gorm.DB,
	username string, // __CYLONIX_MOD__
	machineKey key.MachinePublic,
) (*types.Node, error) {
	// __BEGIN_CYLONIX_MOD__
	user, err := GetUser(tx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user '%v': %w", username, err)
	}
	// __END_CYLONIX_MOD__
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&mach, "user_id = ? AND machine_key = ?", user.ID, machineKey.String()); result.Error != nil { // __CYLONIX_MOD__
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByAnyKey(
	userID *uint, // __CYLONIX_MOD__
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
	oldNodeKey key.NodePublic,
) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByAnyKey(rx, userID, machineKey, nodeKey, oldNodeKey) // __CYLONIX_MOD__
	})
}

// GetNodeByAnyKey finds a Node by its MachineKey, its current NodeKey or the old one, and returns the Node struct.
// TODO(kradalby): see if we can remove this.
func GetNodeByAnyKey(
	tx *gorm.DB,
	userID *uint, // __CYLONIX_MOD__
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*types.Node, error) {
	node := types.Node{}
	tx = tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes")

	// __BEGIN_CYLONIX_MOD__
	if nodeKey.IsZero() && oldNodeKey.IsZero() && machineKey.IsZero() {
		return nil, gorm.ErrRecordNotFound
	}

	if userID != nil && !machineKey.IsZero() {
		where := "(machine_key = ? AND user_id = ?) "
		switch {
		case nodeKey.IsZero() && oldNodeKey.IsZero():
			// Nothing more to add
			if result := tx.First(&node, where, machineKey.String(), *userID); result.Error != nil {
				return nil, result.Error
			}
		case !nodeKey.IsZero() && oldNodeKey.IsZero():
			where += "OR node_key = ?"
			if result := tx.First(&node, where, machineKey.String(), *userID, nodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		case nodeKey.IsZero() && !oldNodeKey.IsZero():
			where += "OR node_key = ?"
			if result := tx.First(&node, where, machineKey.String(), *userID, oldNodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		case !nodeKey.IsZero() && !oldNodeKey.IsZero():
			where += "OR node_key = ? OR node_key = ?"
			if result := tx.First(&node, where, machineKey.String(), *userID, nodeKey.String(), oldNodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		}
	} else {
		if nodeKey.IsZero() {
			where := "node_key = ?"
			if result := tx.First(&node, where, oldNodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		} else if oldNodeKey.IsZero() {
			where := "node_key = ?"
			if result := tx.First(&node, where, nodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		} else {
			where := "node_key = ? OR node_key = ?"
			if result := tx.First(&node, where, nodeKey.String(), oldNodeKey.String()); result.Error != nil {
				return nil, result.Error
			}
		}
	}
	// __END_CYLONIX_MOD__

	return &node, nil
}

func (hsdb *HSDatabase) SetTags(
	nodeID types.NodeID,
	tags []string,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetTags(tx, nodeID, tags)
	})
}

// SetTags takes a Node struct pointer and update the forced tags.
func SetTags(
	tx *gorm.DB,
	nodeID types.NodeID,
	tags []string,
) error {
	if len(tags) == 0 {
		// if no tags are provided, we remove all forced tags
		if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", types.StringList{}).Error; err != nil {
			return fmt.Errorf("failed to remove tags for node in the database: %w", err)
		}

		return nil
	}

	var newTags types.StringList
	for _, tag := range tags {
		if !util.StringOrPrefixListContains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", newTags).Error; err != nil {
		return fmt.Errorf("failed to update tags for node in the database: %w", err)
	}

	return nil
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it.
func RenameNode(tx *gorm.DB,
	nodeID uint64, newName string,
) error {
	err := util.CheckForFQDNRules(
		newName,
	)
	if err != nil {
		return fmt.Errorf("renaming node: %w", err)
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

func (hsdb *HSDatabase) DeleteNode(node *types.Node, isLikelyConnected *xsync.MapOf[types.NodeID, bool], nodeHandler types.NodeHandler) ([]types.NodeID, error) { // __CYLONIX_MOD__
	return Write(hsdb.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return DeleteNode(tx, node, isLikelyConnected, nodeHandler) // __CYLONIX_MOD__
	})
}

// DeleteNode deletes a Node from the database.
// Caller is responsible for notifying all of change.
func DeleteNode(tx *gorm.DB,
	node *types.Node,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
	nodeHandler types.NodeHandler, // __CYLONIX_MOD__
) ([]types.NodeID, error) {
	changed, err := deleteNodeRoutes(tx, node, isLikelyConnected)
	if err != nil {
		return changed, err
	}

	// __BEING_CYLONIX_MOD__
	if nodeHandler != nil {
		if err := nodeHandler.Delete(node); err != nil {
			return changed, err
		}
	}
	// __END_CYLONIX_MOD__

	// Unscoped causes the node to be fully removed from the database.
	if err := tx.Unscoped().Delete(&types.Node{}, node.ID).Error; err != nil {
		return changed, err
	}

	return changed, nil
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

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func SetLastSeen(tx *gorm.DB, nodeID types.NodeID, lastSeen time.Time) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("last_seen", lastSeen).Error
}

func RegisterNodeFromAuthCallback(
	tx *gorm.DB,
	cache *cache.Cache,
	mkey key.MachinePublic,
	userName string,
	nodeExpiry *time.Time,
	registrationMethod string,
	ipv4 *netip.Addr,
	ipv6 *netip.Addr,
	nodeHandler types.NodeHandler, // __CYLONIX_MOD__
) (*types.Node, error) {
	log.Debug().
		Str("machine_key", mkey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", nodeExpiry)).
		Msg("Registering node from API/CLI or auth callback")

	if nodeInterface, ok := cache.Get(mkey.String()); ok {
		if registration, ok := nodeInterface.(types.RegistrationCacheNodeInfo); ok {
			registrationNode := registration.Node
			user, err := GetUser(tx, userName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find user in register node from auth callback, %w",
					err,
				)
			}

			// Registration of expired node with different user
			if registrationNode.ID != 0 &&
				registrationNode.UserID != user.ID {
				return nil, ErrDifferentRegisteredUser
			}

			// __BEGIN_CYLONIX_MOD__
			// Cache has been hit with the callback. Delete it before it
			// to avoid be re-used even for error since the provider of
			// the auth URL may have set the state to be authorized already.
			log.Info().
				Caller().
				Str("machine_key", mkey.ShortString()).
				Str("node_key", registrationNode.NodeKey.ShortString()).
				Msg("Cache hit with auth callback, deleting cache entry")
			cache.Delete(mkey.String())

			node, err := GetNodeByAnyKey(tx, &user.ID, mkey, registrationNode.NodeKey, key.NodePublic{})
			if err == nil {
				node.NodeKey = registrationNode.NodeKey
				registrationNode.RegisterMethod = registrationMethod
				if nodeExpiry != nil {
					node.Expiry = nodeExpiry
				}
				if nodeHandler != nil {
					networDomain, err := nodeHandler.NetworkDomain(&node.User)
					if err != nil {
						return nil, fmt.Errorf("failed to get network domain: %w", err)
					}
					if node.NetworkDomain != string(networDomain) {
						node.NetworkDomain = string(networDomain)
						node.InfoLog().
							Str("old-network-domain", node.NetworkDomain).
							Str("new-network-domain", string(networDomain)).
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
			// __END_CYLONIX_MOD__

			registrationNode.UserID = user.ID
			registrationNode.User = *user
			registrationNode.RegisterMethod = registrationMethod

			if nodeExpiry != nil {
				registrationNode.Expiry = nodeExpiry
			}

			node, err = RegisterNode(
				tx,
				registrationNode,
				ipv4, ipv6,
				nodeHandler, // __CYLONIX_MOD__
			)
			return node, err
		} else {
			return nil, ErrCouldNotConvertNodeInterface
		}
	}

	return nil, ErrNodeNotFoundRegistrationCache
}

func (hsdb *HSDatabase) RegisterNode(node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr, nodeHandler types.NodeHandler) (*types.Node, error) { // __CYLONIX_MOD__
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Node, error) {
		return RegisterNode(tx, node, ipv4, ipv6, nodeHandler) // __CYLONIX_MOD__
	})
}

// RegisterNode is executed from the CLI to register a new Node using its MachineKey.
func RegisterNode(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr, nodeHandler types.NodeHandler) (*types.Node, error) { // __CYLONIX_MOD__
	log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey.ShortString()).
		Str("node_key", node.NodeKey.ShortString()).
		Str("user", node.User.Name).
		Str("Namespace", node.User.GetNamespace()). // __CYLONIX_MOD__
		Msg("Registering node")

	// If the node exists and it already has IP(s), we just save it
	// so we store the node.Expire and node.Nodekey that has been set when
	// adding it to the registrationCache
	if node.IPv4 != nil || node.IPv6 != nil {
		// __BEGIN_CYLONIX_MOD__
		if err := registerNodePreAdd(tx, &node, nodeHandler); err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}
		v, _ := json.Marshal(node.Hostinfo)
		node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
		// __END_CYLONIX_MOD__
		if err := tx.Save(&node).Error; err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Str("machine_key", node.MachineKey.ShortString()).
			Str("node_key", node.NodeKey.ShortString()).
			Str("user", node.User.Name).
			Msg("Node authorized again")

		// __BEGIN_CYLONIX_MOD__
		if nodeHandler != nil {
			nodeHandler.PostAdd(&node)
		}
		// __END_CYLONIX_MOD__

		return &node, nil
	}

	node.IPv4 = ipv4
	node.IPv6 = ipv6

	// __BEGIN_CYLONIX_MOD__
	if err := registerNodePreAdd(tx, &node, nodeHandler); err != nil {
		return nil, fmt.Errorf("failed register(pre-add) node in the database: %w", err)
	}
	node.Namespace = node.User.GetNamespace()
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
		Msg("Node registered with the database")

	return &node, nil
}

// NodeSetNodeKey sets the node key of a node and saves it to the database.
func NodeSetNodeKey(tx *gorm.DB, node *types.Node, nodeKey key.NodePublic) error {
	node.NodeKey = nodeKey // __CYLONIX_ADD__
	return tx.Model(node).Updates(types.Node{
		NodeKeyDatabaseField: nodeKey.String(), // __CYLONIX_ADD__
		NodeKey:              nodeKey,
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
	node.MachineKey = machineKey // __CYLONIX_ADD__
	return tx.Model(node).Updates(types.Node{
		MachineKeyDatabaseField: machineKey.String(), // __CYLONIX_ADD__
		MachineKey:              machineKey,
	}).Error
}

// NodeSave saves a node object to the database, prefer to use a specific save method rather
// than this. It is intended to be used when we are changing or.
// TODO(kradalby): Remove this func, just use Save.
func NodeSave(tx *gorm.DB, node *types.Node) error {
	v, _ := json.Marshal(node.Hostinfo)
	node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")
	return tx.Save(node).Error
}

func (hsdb *HSDatabase) GetAdvertisedRoutes(node *types.Node) ([]netip.Prefix, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]netip.Prefix, error) {
		return GetAdvertisedRoutes(rx, node)
	})
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given node.
func GetAdvertisedRoutes(tx *gorm.DB, node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := tx.
		Preload("Node").
		Where("node_id = ? AND advertised = ?", node.ID, true).Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("getting advertised routes for node(%d): %w", node.ID, err)
	}

	var prefixes []netip.Prefix
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (hsdb *HSDatabase) GetEnabledRoutes(node *types.Node) ([]netip.Prefix, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]netip.Prefix, error) {
		return GetEnabledRoutes(rx, node)
	})
}

// GetEnabledRoutes returns the routes that are enabled for the node.
func GetEnabledRoutes(tx *gorm.DB, node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := tx.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ?", node.ID, true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("getting enabled routes for node(%d): %w", node.ID, err)
	}

	var prefixes []netip.Prefix
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func IsRoutesEnabled(tx *gorm.DB, node *types.Node, routeStr string) bool {
	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := GetEnabledRoutes(tx, node)
	if err != nil {
		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

func (hsdb *HSDatabase) enableRoutes(
	node *types.Node,
	routeStrs ...string,
) (*types.StateUpdate, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return enableRoutes(tx, node, routeStrs...)
	})
}

// enableRoutes enables new routes based on a list of new routes.
func enableRoutes(tx *gorm.DB,
	node *types.Node, routeStrs ...string,
) (*types.StateUpdate, error) {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return nil, err
		}

		newRoutes[index] = route
	}

	advertisedRoutes, err := GetAdvertisedRoutes(tx, node)
	if err != nil {
		return nil, err
	}

	for _, newRoute := range newRoutes {
		if !util.StringOrPrefixListContains(advertisedRoutes, newRoute) {
			return nil, fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				node.Hostname,
				newRoute, ErrNodeRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := types.Route{}
		err := tx.Preload("Node").
			Where("node_id = ? AND prefix = ?", node.ID, types.IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.IsExitRoute() {
				route.IsPrimary = isUniquePrefix(tx, route)
			}

			err = tx.Save(&route).Error
			if err != nil {
				return nil, fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to find route: %w", err)
		}
	}

	// Ensure the node has the latest routes when notifying the other
	// nodes
	nRoutes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to read back routes: %w", err)
	}

	node.Routes = nRoutes

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Strs("routes", routeStrs).
		Msg("enabling routes")

	return &types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "created in db.enableRoutes",

		Namespace:     node.Namespace,     // __CYLONIX_ADD__
		NetworkDomain: node.NetworkDomain, // __CYLONIX_ADD__
	}, nil
}

func generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := util.NormalizeToFQDNRulesConfigFromViper(
		suppliedName,
	)
	normalizedHostname = strings.ReplaceAll(normalizedHostname, ".", "-") // Don't allow '.' in hostname __CYLONIX_ADD__
	if err != nil {
		return "", err
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := util.LabelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		suffix, err := util.GenerateRandomStringDNSSafe(NodeGivenNameHashLength)
		if err != nil {
			return "", err
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (hsdb *HSDatabase) GenerateGivenName(
	mkey key.MachinePublic,
	suppliedName string,
	networkDomain string, nodeID *types.NodeID, currentGivenName *string, // __CYLONIX_MOD__
) (string, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (string, error) {
		return GenerateGivenName(rx, mkey, suppliedName, networkDomain, nodeID, currentGivenName) // __CYLONIX_MOD__
	})
}

var givenNamePattern = regexp.MustCompile(`^(.+?)(?:-([1-9][0-9]?|1[0-2][0-8])?)?$`)

func GenerateGivenName(
	tx *gorm.DB,
	mkey key.MachinePublic,
	suppliedName string,
	networkDomain string, // __CYLONIX_MOD__
	nodeID *types.NodeID, // __CYLONIX_MOD__
	currentGivenName *string, // __CYLONIX_MOD__
) (string, error) {
	givenName, err := generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	// __BEGIN_CYLONIX_MOD__
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
	// __END_CYLONIX_MOD__
}

// TODO: (randy) Make this per network domain or namespace __CYLONIX_ADD__
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
	e.cancelCh <- struct{}{}
}

// Schedule schedules a node for deletion after the expiry duration.
func (e *EphemeralGarbageCollector) Schedule(nodeID types.NodeID, expiry time.Duration) {
	e.mu.Lock()
	timer := time.NewTimer(expiry)
	e.toBeDeleted[nodeID] = timer
	e.mu.Unlock()

	go func() {
		select {
		case _, ok := <-timer.C:
			if ok {
				e.deleteCh <- nodeID
			}
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

// __BEGIN_CYLONIX_MOD__
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
		err := util.CheckForFQDNRules(
			update.GivenName,
		)
		if err != nil {
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

	// Delete current associated routes if the 'Routes' field is not 'nil'.
	// Note for updates that do not intend to delete all the routes,
	// 'update.Routes' must be 'nil' instead of '[]'.
	if update.Routes != nil {
		if err := tx.Model(&types.Route{}).Unscoped().
			Delete(&types.Route{}, "node_id = ?", id).
			Error; err != nil {
			return err
		}
	}
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

func registerNodePreAdd(tx *gorm.DB, node *types.Node, nodeHandler types.NodeHandler) error {
	if nodeHandler == nil {
		return nil
	}
	if _, err := nodeHandler.PreAdd(node); err != nil {
		return fmt.Errorf("failed register existing node in the database: %w", err)
	}
	// Regenerate the given name since we now have the node user information.
	v, err := nodeHandler.NetworkDomain(&node.User)
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
	node.InfoLog().Msg("Generated given name for node")

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
	if node.Health != nil && *node.Health == s {
		// No change
		return nil
	}

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
		Preload("Routes").
		Preload("Capabilities").
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
		Preload("Routes").
		Preload("Capabilities").
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

// __END_CYLONIX_MOD__
