// nolint
package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

type headscaleV1APIServer struct { // v1.HeadscaleServiceServer
	v1.UnimplementedHeadscaleServiceServer
	h *Headscale
}

func newHeadscaleV1APIServer(h *Headscale) v1.HeadscaleServiceServer {
	return headscaleV1APIServer{
		h: h,
	}
}

func (api headscaleV1APIServer) GetUser(
	ctx context.Context,
	request *v1.GetUserRequest,
) (*v1.GetUserResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(request.GetNamespace(), request.GetName(), request.GetNetwork())); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	user, err := api.h.db.GetUser(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.GetUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) CreateUser(
	ctx context.Context,
	request *v1.CreateUserRequest,
) (*v1.CreateUserResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(request.GetNamespace(), request.GetName(), request.GetNetwork())); err != nil {
		return nil, err
	}
	user, err := api.h.db.CreateNamespaceUser(request.GetName(), request.Namespace, request.LoginName, request.GetNetwork())
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	return &v1.CreateUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) RenameUser(
	ctx context.Context,
	request *v1.RenameUserRequest,
) (*v1.RenameUserResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(request.GetNamespace(), request.GetOldName(), request.GetNetwork())); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	err := api.h.db.RenameUser(request.GetOldName(), request.GetNewName())
	if err != nil {
		return nil, err
	}

	user, err := api.h.db.GetUser(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) DeleteUser(
	ctx context.Context,
	request *v1.DeleteUserRequest,
) (*v1.DeleteUserResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(request.GetNamespace(), request.GetName(), request.GetNetwork())); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	err := api.h.db.DestroyUser(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.DeleteUserResponse{}, nil
}

func (api headscaleV1APIServer) ListUsers(
	ctx context.Context,
	request *v1.ListUsersRequest,
) (*v1.ListUsersResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	total, users, err := api.h.db.ListUsersWithOptions(
		request.GetIdList(),
		request.Namespace,
		request.GetNetwork(),
		request.GetUser(),
		request.GetFilterBy(),
		request.GetFilterValue(),
		request.GetSortBy(),
		request.GetSortDesc(),
		int(request.GetPage()),
		int(request.GetPageSize()),
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	response := make([]*v1.User, len(users))
	for index, user := range users {
		response[index] = user.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	log.Trace().Caller().Interface("users", response).Msg("")

	return &v1.ListUsersResponse{Users: response, Total: uint32(total)}, nil // __CYLONIX_MOD__
}

func (api headscaleV1APIServer) CreatePreAuthKey(
	ctx context.Context,
	request *v1.CreatePreAuthKeyRequest,
) (*v1.CreatePreAuthKeyResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	network := ""
	if request.GetUser() != "" {
		user, err := api.h.db.GetUser(request.GetUser())
		if err != nil {
			return nil, err
		}
		network = user.Network
	}
	r := types.NewAuthScope(request.GetNamespace(), request.GetUser(), network)
	if err := api.auth(ctx, r); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	for _, tag := range request.AclTags {
		err := validateTag(tag)
		if err != nil {
			return &v1.CreatePreAuthKeyResponse{
				PreAuthKey: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	preAuthKey, err := api.h.db.CreatePreAuthKey(
		request.GetUser(),
		request.GetReusable(),
		request.GetEphemeral(),
		request.GetDescription(), // __CYLONIX_MOD__
		request.GetIpv4(),        // __CYLONIX_MOD__
		request.GetIpv6(),        // __CYLONIX_MOD__
		&expiration,
		request.AclTags,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreatePreAuthKeyResponse{PreAuthKey: preAuthKey.Proto()}, nil
}

// __BEGIN_CYLONIX_MOD__
func (api headscaleV1APIServer) DeletePreAuthKey(
	ctx context.Context,
	request *v1.DeletePreAuthKeyRequest,
) (*v1.DeletePreAuthKeyResponse, error) {
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}

	preAuthKey, err := api.h.db.GetPreAuthKeyByID(request.GetId())
	if err != nil {
		if errors.Is(err, db.ErrPreAuthKeyNotFound) {
			return &v1.DeletePreAuthKeyResponse{}, nil
		}
		return nil, fmt.Errorf("failed to find the pre auth key: %w", err)
	}

	if err := api.auth(ctx, types.NewAuthScope(
		preAuthKey.Namespace, preAuthKey.User.Name, preAuthKey.User.Network,
	)); err != nil {
		return nil, err
	}

	err = api.h.db.DeletePreAuthKey(*preAuthKey)
	if err != nil {
		return nil, err
	}

	return &v1.DeletePreAuthKeyResponse{}, nil
}

// __END_CYLONIX_MOD__

func (api headscaleV1APIServer) ExpirePreAuthKey(
	ctx context.Context,
	request *v1.ExpirePreAuthKeyRequest,
) (*v1.ExpirePreAuthKeyResponse, error) {
	err := api.h.db.Write(func(tx *gorm.DB) error {
		// __BEGIN_CYLONIX_ADD__
		// First check if auth token exists.
		if err := api.auth(ctx, nil); err != nil {
			return err
		}
		// __END_CYLONIX_ADD__
		var (
			preAuthKey *types.PreAuthKey
			err        error
		)

		// __BEGIN_CYLONIX_MOD__
		if request.Id != nil {
			preAuthKey, err = db.GetPreAuthKeyByID(tx, request.GetId())
			if err != nil {
				log.Debug().Int("id", int(request.GetId())).
					Err(err).Msg("Failed to get pre auth key by ID")
			}
		} else {
			preAuthKey, err = db.GetPreAuthKey(tx, request.GetUser(), request.GetKey())
			if err != nil {
				log.Debug().
					Str("user", request.GetUser()).
					Str("key", request.GetKey()).
					Err(err).Msg("Failed to get pre auth key by user and key")
			}
		}
		if err != nil {
			return err
		}

		if err := api.auth(ctx, types.NewAuthScope(
			preAuthKey.Namespace, preAuthKey.User.Name, preAuthKey.User.Network,
		)); err != nil {
			return err
		}

		// Check if expiry time is set in the request. 0 means disable expiry.
		now := time.Now()
		if request.Expiry != nil {
			if request.Expiry.AsTime().IsZero() {
				now = time.Time{}
			} else {
				now = request.Expiry.AsTime()
			}
		}

		return db.ExpirePreAuthKey(tx, preAuthKey, now)
		// __END_CYLONIX_MOD__
	})
	if err != nil {
		return nil, err
	}

	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	network := ""
	if request.GetUser() != "" {
		user, err := api.h.db.GetUser(request.GetUser())
		if err != nil {
			return nil, err
		}
		network = user.Network
	}
	r := types.NewAuthScope(request.GetNamespace(), request.GetUser(), network)
	scope, err := api.authAndScope(ctx, r)
	if err != nil {
		return nil, err
	}
	total, preAuthKeys, err := api.h.db.ListPreAuthKeysWithOptions(
		request.GetIdList(),
		request.Namespace,
		scope == types.AuthScopeTypeFull,
		"", // network is not yet supported
		request.GetUser(),
		request.GetFilterBy(),
		request.GetFilterValue(),
		request.GetSortBy(),
		request.GetSortDesc(),
		int(request.GetPage()),
		int(request.GetPageSize()),
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	response := make([]*v1.PreAuthKey, len(preAuthKeys))
	for index, key := range preAuthKeys {
		response[index] = key.Proto()
		response[index].Key = db.GetPreAuthKeyDisplayKey(key.Key) // __CYLONIX_MOD__
	}

	// __BEGIN_CYLONIX_MOD__
	// Only sort by ID if there is no sorting specified in the request.
	if request.SortBy == nil {
		sort.Slice(response, func(i, j int) bool {
			return response[i].Id < response[j].Id
		})
	}
	// __END_CYLONIX_MOD__

	return &v1.ListPreAuthKeysResponse{Total: uint32(total), PreAuthKeys: response}, nil // __CYLONIX_MOD__
}

func (api headscaleV1APIServer) RegisterNode(
	ctx context.Context,
	request *v1.RegisterNodeRequest,
) (*v1.RegisterNodeResponse, error) {
	log.Trace().
		Str("user", request.GetUser()).
		Str("machine_key", request.GetKey()).
		Msg("Registering node")

	var mkey key.MachinePublic
	err := mkey.UnmarshalText([]byte(request.GetKey()))
	if err != nil {
		return nil, err
	}

	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	user, err := api.h.db.GetUser(request.GetUser())
	if err != nil {
		return nil, err
	}

	ipv4, ipv6, err := api.h.ipAlloc.NextFor(user, &mkey, nil, nil)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		return db.RegisterNodeFromAuthCallback(
			tx,
			api.h.registrationCache,
			mkey,
			request.GetUser(),
			nil,
			util.RegisterMethodCLI,
			ipv4, ipv6,
			api.h.cfg.NodeHandler, // __CYLONIX_MOD__
		)
	})
	if err != nil {
		api.h.ipAlloc.FreeFor(ipv4, user, &mkey) // __CYLONIX_MOD__
		api.h.ipAlloc.FreeFor(ipv6, user, &mkey) // __CYLONIX_MOD__
		return nil, err
	}

	api.h.postRegistrationHandling(node) // __CYLONIX_ADD__

	return &v1.RegisterNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) GetNode(
	ctx context.Context,
	request *v1.GetNodeRequest,
) (*v1.GetNodeResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__

	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	resp := node.Proto()

	// Populate the online field based on
	// currently connected nodes.
	resp.Online = api.h.nodeNotifier.IsConnected(node.ID)

	// __BEGIN_CYLONIX_ADD__
	if node.IsWireguardOnly != nil && *node.IsWireguardOnly {
		if node.LastSeen == nil {
			resp.Online = true
		}
	}
	// __END_CYLONIX_ADD__

	return &v1.GetNodeResponse{Node: resp}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	// Further check permissions for the specific node.
	{
		node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
		if err != nil {
			return nil, err
		}
		if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
			return nil, err
		}
	}
	// __END_CYLONIX_ADD__

	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return nil, err
		}
	}

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetTags(tx, types.NodeID(request.GetNodeId()), request.GetTags())
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx = types.NotifyCtx(ctx, "cli-settags", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "called from api.SetTags",

		Namespace:     node.Namespace,     // __CYLONIX_ADD__
		NetworkDomain: node.NetworkDomain, // __CYLONIX_ADD__
	}, node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Strs("tags", request.GetTags()).
		Msg("Changing tags of node")

	return &v1.SetTagsResponse{Node: node.Proto()}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return errors.New("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return errors.New("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return errors.New("tag should not contains space")
	}
	return nil
}

func (api headscaleV1APIServer) DeleteNode(
	ctx context.Context,
	request *v1.DeleteNodeRequest,
) (*v1.DeleteNodeResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__

	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		// __BEGIN_CYLONIX_MOD__
		if errors.Is(err, db.ErrNodeNotFound) {
			return &v1.DeleteNodeResponse{}, nil
		}
		// __END_CYLONIX_MOD__
		return nil, err
	}
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	changedNodes, err := api.h.db.DeleteNode(
		node,
		api.h.nodeNotifier.LikelyConnectedMap(),
		api.h.cfg.NodeHandler, // __CYLONIX_MOD__
	)
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-deletenode", node.Hostname)
	api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
		Type:    types.StatePeerRemoved,
		Removed: []types.NodeID{node.ID},
	})

	if changedNodes != nil {
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: changedNodes,

			Namespace:     node.Namespace,     // __CYLONIX_ADD__
			NetworkDomain: node.NetworkDomain, // __CYLONIX_ADD__
		})
	}

	return &v1.DeleteNodeResponse{}, nil
}

func (api headscaleV1APIServer) ExpireNode(
	ctx context.Context,
	request *v1.ExpireNodeRequest,
) (*v1.ExpireNodeResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	{
		// First check if auth token exists.
		if err := api.auth(ctx, nil); err != nil {
			return nil, err
		}
		node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
		if err != nil {
			return nil, err
		}
		if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
			return nil, err
		}
	}
	// __END_CYLONIX_ADD__
	now := time.Now()

	// __BEGIN_CYLONIX_ADD__
	// Check if expiry time is set in the request. 0 means disable expiry.
	if request.Expiry != nil {
		if request.Expiry.AsTime().IsZero() {
			now = time.Time{}
		} else {
			now = request.Expiry.AsTime()
		}
	}
	// __END_CYLONIX_ADD__

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		db.NodeSetExpiry(
			tx,
			types.NodeID(request.GetNodeId()),
			now,
		)

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-expirenode-self", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(
		ctx,
		types.StateUpdate{
			Type:        types.StateSelfUpdate,
			ChangeNodes: []types.NodeID{node.ID},

			Namespace:     node.Namespace,     // __CYLONIX_ADD__
			NetworkDomain: node.NetworkDomain, // __CYLONIX_ADD__
		},
		node.ID)

	ctx = types.NotifyCtx(ctx, "cli-expirenode-peers", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, now), node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Time("expiry", *node.Expiry).
		Msg("node set expiry") // __CYLONIX_MOD__

	return &v1.ExpireNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) RenameNode(
	ctx context.Context,
	request *v1.RenameNodeRequest,
) (*v1.RenameNodeResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	{
		// First check if auth token exists.
		if err := api.auth(ctx, nil); err != nil {
			return nil, err
		}
		node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
		if err != nil {
			return nil, err
		}
		if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
			return nil, err
		}
	}
	// __END_CYLONIX_ADD__
	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.RenameNode(
			tx,
			request.GetNodeId(),
			request.GetNewName(),
		)
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-renamenode", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "called from api.RenameNode",

		Namespace:     node.Namespace,     // __CYLONIX_ADD__
		NetworkDomain: node.NetworkDomain, // __CYLONIX_ADD__
	}, node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Str("new_name", request.GetNewName()).
		Msg("node renamed")

	return &v1.RenameNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) ListNodes(
	ctx context.Context,
	request *v1.ListNodesRequest,
) (*v1.ListNodesResponse, error) {
	isLikelyConnected := api.h.nodeNotifier.LikelyConnectedMap()
	// __BEGIN_CYLONIX_MOD__
	scope, err := api.authAndScope(ctx, request)
	if err != nil {
		return nil, err
	}
	var onlineIDs []uint64
	if request.GetOnlineOnly() {
		list := api.h.nodeNotifier.ConnectedNodeIDs()
		onlineIDs = make([]uint64, 0, len(list))
		for _, id := range list {
			onlineIDs = append(onlineIDs, uint64(id))
		}
	}
	total, nodes, err := api.h.db.ListNodesWithOptions(
		request.GetNodeIdList(),
		request.Namespace,
		request.GetNetwork(),
		request.GetUser(),
		request.GetOnlineOnly(),
		scope == types.AuthScopeTypeFull,
		request.GetShareInOnly(),
		onlineIDs,
		request.GetFilterBy(),
		request.GetFilterValue(),
		request.GetSortBy(),
		request.GetSortDesc(),
		int(request.GetPage()),
		int(request.GetPageSize()),
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list nodes")
		return nil, err
	}

	// __BEGIN_CYLONIX_MOD__
	// Only sort by ID if there is no sorting specified in the request.
	if request.SortBy == nil {
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].ID < nodes[j].ID
		})
	}
	// __END_CYLONIX_MOD__

	response := make([]*v1.Node, len(nodes))
	pols := make(map[string]*policy.ACLPolicy)
	for index, node := range nodes {
		resp := node.Proto()

		// Populate the online field based on
		// currently connected nodes.
		if val, ok := isLikelyConnected.Load(node.ID); ok && val {
			resp.Online = true
		} else {
			// __BEGIN_CYLONIX_ADD__
			if node.IsWireguardOnly != nil && *node.IsWireguardOnly {
				if node.LastSeen == nil {
					resp.Online = true
				}
			}
			// __END_CYLONIX_ADD__
		}

		// __BEGIN_CYLONIX_MOD__
		var (
			pol *policy.ACLPolicy
			ok  = false
		)
		if node.NetworkDomain == "" || node.Namespace != "" {
			if api.h.cfg.Policy.Mode != types.PolicyModeMulti {
				pol, err = api.h.ACLPolicy(nil, nil)
				if err != nil {
					return nil, err
				}
			}
		} else {
			if pol, ok = pols[node.Namespace+node.NetworkDomain]; !ok {
				pol, err = api.h.ACLPolicy(&node.Namespace, &node.NetworkDomain)
				if err != nil {
					//return nil, err
				}
				pols[node.Namespace+node.NetworkDomain] = pol
			}
		}

		if pol != nil {
			validTags, invalidTags := pol.TagsOfNode(
				node,
			)
			resp.InvalidTags = invalidTags
			resp.ValidTags = validTags
		}
		// __END_CYLONIX_MOD__
		response[index] = resp
	}

	return &v1.ListNodesResponse{Total: uint32(total), Nodes: response}, nil // __CYLONIX_MOD__
}

func (api headscaleV1APIServer) MoveNode(
	ctx context.Context,
	request *v1.MoveNodeRequest,
) (*v1.MoveNodeResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}
	// __BEGIN_CYLONIX_ADD__
	if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__

	err = api.h.db.AssignNodeToUser(node, request.GetUser())
	if err != nil {
		return nil, err
	}

	return &v1.MoveNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) BackfillNodeIPs(
	ctx context.Context,
	request *v1.BackfillNodeIPsRequest,
) (*v1.BackfillNodeIPsResponse, error) {
	log.Trace().Msg("Backfill called")
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	if !request.Confirmed {
		return nil, errors.New("not confirmed, aborting")
	}

	changes, err := api.h.db.BackfillNodeIPs(api.h.ipAlloc)
	if err != nil {
		return nil, err
	}

	return &v1.BackfillNodeIPsResponse{Changes: changes}, nil
}

func (api headscaleV1APIServer) GetRoutes(
	ctx context.Context,
	request *v1.GetRoutesRequest,
) (*v1.GetRoutesResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	total, routes, err := api.h.db.ListRoutesWithOptions(
		request.GetIdList(),
		request.Namespace,
		request.GetNetwork(),
		request.GetUser(),
		request.GetFilterBy(),
		request.GetFilterValue(),
		request.GetSortBy(),
		request.GetSortDesc(),
		int(request.GetPage()),
		int(request.GetPageSize()),
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	return &v1.GetRoutesResponse{
		Total:  uint32(total), // __CYLONIX_MOD__
		Routes: types.Routes(routes).Proto(),
	}, nil
}

func (api headscaleV1APIServer) EnableRoute(
	ctx context.Context,
	request *v1.EnableRouteRequest,
) (*v1.EnableRouteResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	route, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (*types.Route, error) {
		return db.GetRoute(rx, request.GetRouteId())
	})
	if err != nil {
		return nil, err
	}
	if err := api.auth(ctx, types.NewAuthScope(route.Node.Namespace, route.Node.User.Name, route.Node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return db.EnableRoute(tx, request.GetRouteId())
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-enableroute", "unknown")
		api.h.nodeNotifier.NotifyAll(
			ctx, *update)
	}

	return &v1.EnableRouteResponse{}, nil
}

func (api headscaleV1APIServer) DisableRoute(
	ctx context.Context,
	request *v1.DisableRouteRequest,
) (*v1.DisableRouteResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	route, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (*types.Route, error) {
		return db.GetRoute(rx, request.GetRouteId())
	})
	if err != nil {
		return nil, err
	}
	if err := api.auth(ctx, types.NewAuthScope(route.Node.Namespace, route.Node.User.Name, route.Node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return db.DisableRoute(tx, request.GetRouteId(), api.h.nodeNotifier.LikelyConnectedMap())
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-disableroute", "unknown")
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: update,

			Namespace:     route.Node.Namespace,     // __CYLONIX_ADD__
			NetworkDomain: route.Node.NetworkDomain, // __CYLONIX_ADD__
		})
	}

	return &v1.DisableRouteResponse{}, nil
}

func (api headscaleV1APIServer) GetNodeRoutes(
	ctx context.Context,
	request *v1.GetNodeRoutesRequest,
) (*v1.GetNodeRoutesResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}
	// __BEGIN_CYLONIX_ADD__
	if err := api.auth(ctx, types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_ADD__

	routes, err := api.h.db.GetNodeRoutes(node)
	if err != nil {
		return nil, err
	}

	return &v1.GetNodeRoutesResponse{
		Routes: types.Routes(routes).Proto(),
	}, nil
}

func (api headscaleV1APIServer) DeleteRoute(
	ctx context.Context,
	request *v1.DeleteRouteRequest,
) (*v1.DeleteRouteResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	route, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (*types.Route, error) {
		return db.GetRoute(rx, request.GetRouteId())
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &v1.DeleteRouteResponse{}, nil
		}
		return nil, err
	}
	if err := api.auth(ctx, types.NewAuthScope(route.Node.Namespace, route.Node.User.Name, route.Node.NetworkDomain)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	isConnected := api.h.nodeNotifier.LikelyConnectedMap()
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return db.DeleteRoute(tx, request.GetRouteId(), isConnected)
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-deleteroute", "unknown")
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: update,

			Namespace:     route.Node.Namespace,     // __CYLONIX_ADD__
			NetworkDomain: route.Node.NetworkDomain, // __CYLONIX_ADD__
		})
	}

	return &v1.DeleteRouteResponse{}, nil
}

func (api headscaleV1APIServer) CreateApiKey(
	ctx context.Context,
	request *v1.CreateApiKeyRequest,
) (*v1.CreateApiKeyResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	apiKey, _, err := api.h.db.CreateAPIKey(
		&expiration,
		request.GetUser(),       // __CYLONIX_MOD__
		request.GetNetwork(),    // __CYLONIX_MOD__
		request.GetNamespace(),  // __CYLONIX_MOD__
		request.GetScopeType(),  // __CYLONIX_MOD__
		request.GetScopeValue(), // __CYLONIX_MOD__
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreateApiKeyResponse{ApiKey: apiKey}, nil
}

func (api headscaleV1APIServer) ExpireApiKey(
	ctx context.Context,
	request *v1.ExpireApiKeyRequest,
) (*v1.ExpireApiKeyResponse, error) {
	var apiKey *types.APIKey
	var err error

	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	if request.Prefix == "" {
		// Expiring the api key used to invoke this API.
		apiKey, err = api.getAPIKeyFromIncomingContext(ctx)
	} else {
		apiKey, err = api.h.db.GetAPIKey(request.Prefix)
	}
	// __END_CYLONIX_MOD__

	if err != nil {
		return nil, err
	}
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(apiKey.Namespace, "", "")); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	err = api.h.db.ExpireAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	total, apiKeys, err := api.h.db.ListAPIKeysWithOptions(
		request.GetNodeIdList(),
		request.Namespace,
		request.GetNetwork(),
		request.GetUser(),
		request.GetFilterBy(),
		request.GetFilterValue(),
		request.GetSortBy(),
		request.GetSortDesc(),
		int(request.GetPage()),
		int(request.GetPageSize()),
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	response := make([]*v1.ApiKey, len(apiKeys))
	for index, key := range apiKeys {
		response[index] = key.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListApiKeysResponse{ApiKeys: response, Total: uint32(total)}, nil // __CYLONIX_MOD__
}

func (api headscaleV1APIServer) DeleteApiKey(
	ctx context.Context,
	request *v1.DeleteApiKeyRequest,
) (*v1.DeleteApiKeyResponse, error) {
	var (
		apiKey *types.APIKey
		err    error
		prefix = request.Prefix // __CYLONIX_MOD__
	)

	// __BEGIN_CYLONIX_MOD__
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	if request.Prefix == "" {
		// Deleting the api key used to invoke this API.
		apiKey, err = api.getAPIKeyFromIncomingContext(ctx)
		prefix = apiKey.Prefix
	} else {
		apiKey, err = api.h.db.GetAPIKey(prefix)
	}
	// __END_CYLONIX_MOD__
	if err != nil {
		// __BEGIN_CYLONIX_MOD__
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &v1.DeleteApiKeyResponse{}, nil
		}
		log.Error().Err(err).Str("prefix", prefix).Msg("failed to fetch api key")
		// __END_CYLONIX_MOD__
		return nil, err
	}
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, types.NewAuthScope(apiKey.Namespace, apiKey.Username(), apiKey.Network)); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	if err := api.h.db.DestroyAPIKey(*apiKey); err != nil {
		// __BEGIN_CYLONIX_MOD__
		log.Error().
			Err(err).
			Str("prefix", prefix).
			Str("namespace", apiKey.Namespace).
			Str("user", apiKey.Username()).
			Msg("failed to delete api key")
		// __END_CYLONIX_MOD__
		return nil, err
	}

	return &v1.DeleteApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) GetPolicy(
	ctx context.Context, // __CYLONIX_MOD__
	request *v1.GetPolicyRequest, // __CYLONIX_MOD__
) (*v1.GetPolicyResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__

	log.Debug().
		Str("namespace", request.GetNamespace()).
		Str("network", request.GetNetwork()).
		Str("policy-mode", string(api.h.cfg.Policy.Mode)).
		Msg("GetPolicy")
	switch api.h.cfg.Policy.Mode {
	case types.PolicyModeDB, types.PolicyModeMulti: // __CYLONIX_MOD__
		p, err := api.h.db.GetPolicy(request.Namespace, request.Network)
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				// If the policy is not found, return an empty policy.
				return &v1.GetPolicyResponse{
					Policy:    "",
					UpdatedAt: nil,
				}, nil
			}
			return nil, err
		}

		return &v1.GetPolicyResponse{
			Policy:    p.Data,
			UpdatedAt: timestamppb.New(p.UpdatedAt),
		}, nil
	case types.PolicyModeFile:
		// Read the file and return the contents as-is.
		absPath := util.AbsolutePathFromConfigPath(api.h.cfg.Policy.Path)
		f, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}

		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}

		return &v1.GetPolicyResponse{Policy: string(b)}, nil
	}

	return nil, nil
}

func (api headscaleV1APIServer) SetPolicy(
	ctx context.Context, // __CYLONIX_MOD__
	request *v1.SetPolicyRequest,
) (*v1.SetPolicyResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	if api.h.cfg.Policy.Mode != types.PolicyModeMulti {
		if request.Namespace != nil || request.Network != nil {
			return nil, fmt.Errorf("namespace and network are not supported in this mode")
		}
	}
	if api.h.cfg.Policy.Mode == types.PolicyModeFile { // __CYLONIX_MOD__
		return nil, types.ErrPolicyUpdateIsDisabled
	}

	p := request.GetPolicy()

	pol, err := policy.LoadACLPolicyFromBytes([]byte(p))
	if err != nil {
		return nil, fmt.Errorf("loading ACL policy file: %w", err)
	}

	// Validate and reject configuration that would error when applied
	// when creating a map response. This requires nodes, so there is still
	// a scenario where they might be allowed if the server has no nodes
	// yet, but it should help for the general case and for hot reloading
	// configurations.
	// __BEGIN_CYLONIX_MOD__
	_, nodes, err := api.h.db.ListNodesWithOptions(
		nil, request.Namespace, request.GetNetwork(), "", false, false, false,
		nil, "", "", "", "", 0, 0,
	)
	// __END_CYLONIX_MOD__
	if err != nil {
		return nil, fmt.Errorf("loading nodes from database to validate policy: %w", err)
	}

	_, err = pol.CompileFilterRules(nodes)
	if err != nil {
		return nil, fmt.Errorf("verifying policy rules: %w", err)
	}

	if len(nodes) > 0 {
		_, err = pol.CompileSSHPolicy(nodes[0], nodes)
		if err != nil {
			return nil, fmt.Errorf("verifying SSH rules: %w", err)
		}
	}

	updated, err := api.h.db.SetPolicy(p, request.GetNamespace(), request.GetNetwork()) // __CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	// __BEGIN_CYLONIX_MOD__
	if api.h.cfg.Policy.Mode != types.PolicyModeMulti {
		api.h.SetACLPolicy(pol)
	}
	// __END_CYLONIX_MOD__

	ctx = types.NotifyCtx(context.Background(), "acl-update", "na") // __CYLONIX_MOD_-
	api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
		Type: types.StateFullUpdate,

		Namespace:     request.GetNamespace(), // __CYLONIX_ADD__
		NetworkDomain: request.GetNetwork(),   // __CYLONIX_ADD__
	})

	response := &v1.SetPolicyResponse{
		Policy:    updated.Data,
		UpdatedAt: timestamppb.New(updated.UpdatedAt),
	}

	return response, nil
}

// The following service calls are for testing and debugging
func (api headscaleV1APIServer) DebugCreateNode(
	ctx context.Context,
	request *v1.DebugCreateNodeRequest,
) (*v1.DebugCreateNodeResponse, error) {
	// __BEGIN_CYLONIX_MOD__
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	// __END_CYLONIX_MOD__
	user, err := api.h.db.GetUser(request.GetUser())
	if err != nil {
		return nil, err
	}

	routes, err := util.StringToIPPrefix(request.GetRoutes())
	if err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Interface("route-prefix", routes).
		Interface("route-str", request.GetRoutes()).
		Msg("")

	hostinfo := tailcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    "DebugTestNode",
	}

	var mkey key.MachinePublic
	err = mkey.UnmarshalText([]byte(request.GetKey()))
	if err != nil {
		return nil, err
	}

	givenName, err := api.h.db.GenerateGivenName(mkey, request.GetName(), "", nil, nil) // __CYLONIX_MOD__
	if err != nil {
		return nil, err
	}

	nodeKey := key.NewNode()

	newNode := types.Node{
		MachineKey: mkey,
		NodeKey:    nodeKey.Public(),
		Hostname:   request.GetName(),
		GivenName:  givenName,
		User:       *user,

		Expiry:   &time.Time{},
		LastSeen: &time.Time{},

		Hostinfo: &hostinfo,
	}

	log.Debug().
		Str("machine_key", mkey.ShortString()).
		Msg("adding debug machine via CLI, appending to registration cache")

	api.h.registrationCache.Set(
		mkey.String(),
		newNode,
		registerCacheExpiration,
	)

	return &v1.DebugCreateNodeResponse{Node: newNode.Proto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}

// __BEGIN_CYLONIX_MOD__
func (api headscaleV1APIServer) getAPIKeyFromIncomingContext(ctx context.Context) (*types.APIKey, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no meta data from incoming context")
	}
	authHeader, ok := meta["authorization"]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authorization token")
	}
	token := authHeader[0]
	if !strings.HasPrefix(token, AuthPrefix) {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("missing '%v' prefix in token", AuthPrefix))
	}

	key, valid, err := api.h.db.GetAndValidateAPIKey(strings.TrimPrefix(token, AuthPrefix))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("api key '%v' invalid", token))
		}
		return nil, err
	}
	if !valid {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("api key '%v' invalid", token))
	}
	return key, err
}
func (api headscaleV1APIServer) authNoLog(ctx context.Context, request interface{}) (types.AuthScopeType, error) {
	// Local native GRPC access will set the ctx with full scope. Skip auth
	// check if it has been set with full access scope.
	if types.IsWithFullAuthScope(ctx) {
		return types.AuthScopeTypeFull, nil
	}
	key, err := api.getAPIKeyFromIncomingContext(ctx)
	if err != nil {
		return types.AuthScopeTypeNone, err
	}
	// Nil request means we just want to validate the key exists.
	if request == nil {
		return types.AuthScopeTypeNone, nil
	}
	scope, ok := key.Auth(request)
	if !ok {
		return types.AuthScopeTypeNone, status.Error(codes.PermissionDenied, "unauthorized scope")
	}
	return scope, nil
}

func (api headscaleV1APIServer) authAndScope(ctx context.Context, request interface{}) (types.AuthScopeType, error) {
	scope, err := api.authNoLog(ctx, request)
	if err != nil {
		path := ""
		if meta, ok := metadata.FromIncomingContext(ctx); ok {
			if s, ok := meta["path"]; ok {
				path = s[0]
			}
		}
		log.Debug().Err(err).Str("path", path).Msg("request authorization failed")
	}
	return scope, err
}

func (api headscaleV1APIServer) auth(ctx context.Context, request interface{}) error {
	_, err := api.authAndScope(ctx, request)
	return err
}

func (api headscaleV1APIServer) RefreshApiKey(
	ctx context.Context,
	request *v1.RefreshApiKeyRequest,
) (*v1.RefreshApiKeyResponse, error) {
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}
	prefix := strings.TrimPrefix(request.Prefix, AuthPrefix)
	key, valid, err := api.h.db.GetAndValidateAPIKey(prefix)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("api key '%v' invalid", prefix))
		}
		log.Error().Err(err).Str("prefix", prefix).Msg("Failed to fetch")
		return nil, err
	}
	if !valid {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("api key '%v' invalid", prefix))
	}
	if err := api.auth(ctx, types.NewAuthScope(key.Namespace, key.Username(), key.Network)); err != nil {
		return nil, err
	}
	expire := time.Now().Add(time.Minute * 30)
	if key.Expiration == nil || key.Expiration.IsZero() || expire.Before(*key.Expiration) {
		return &v1.RefreshApiKeyResponse{}, nil
	}
	if err := api.h.db.RefreshAPIKey(key.ID, expire); err != nil {
		log.Error().
			Err(err).
			Str("prefix", prefix).
			Str("namespace", key.Namespace).
			Str("user", key.Username()).
			Msg("Failed to refresh")
		return nil, err
	}
	return &v1.RefreshApiKeyResponse{}, nil
}
func (api headscaleV1APIServer) CreateNode(
	ctx context.Context,
	request *v1.CreateNodeRequest,
) (*v1.CreateNodeResponse, error) {
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}

	n := request.Node
	logger := log.Error().Str("namespace", n.Namespace).Str("name", n.Name).
		Str("machine-key", n.MachineKey)
	node, err := types.ParseProtoNode(n, false)
	if err != nil {
		logger.Err(err).Msg("Failed to parse node")
		return nil, err
	}

	if node.GivenName == "" {
		givenName, err := api.h.db.GenerateGivenName(node.MachineKey, n.Name, node.NetworkDomain, nil, nil) // __CYLONIX_MOD__
		if err != nil {
			logger.Err(err).Msg("Failed to generate given name")
			return nil, err
		}
		node.GivenName = givenName
	}
	if err = api.h.db.DB.Create(node).Error; err != nil {
		logger.Err(err).Msg("Failed to save node to db")
		return nil, err
	}

	log.Info().Str("namespace", n.Namespace).Str("name", n.Name).
		Str("machine_key", n.MachineKey).
		Msg("Added node")

	return &v1.CreateNodeResponse{NodeId: uint64(node.ID)}, nil
}
func (api headscaleV1APIServer) UpdateNode(
	ctx context.Context,
	request *v1.UpdateNodeRequest,
) (*v1.UpdateNodeResponse, error) {
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}

	node, err := api.h.db.GetNodeByID(types.NodeID(request.NodeId))
	if err != nil {
		return nil, err
	}
	s := types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)
	if err := api.auth(ctx, s); err != nil {
		return nil, err
	}

	var (
		n      = request.Update
		update = &types.Node{}
		logger = log.Error().
			Str("namespace", request.Namespace).
			Uint64("node-id", request.NodeId)
	)
	if n != nil {
		if n.Capabilities != nil && len(n.Capabilities) == 0 {
			log.Warn().
				Caller().
				Str("namespace", request.Namespace).
				Uint64("node-id", request.NodeId).
				Str("node-name", n.Name).
				Msg("Capabilities field is not-nil but empty. This will remove all existing capabilities.")
		}
		update, err = types.ParseProtoNode(n, true)
		if err != nil {
			logger.Err(err).Msg("Failed to parse node")
			return nil, err
		}
		logger = logger.
			Str("name", update.GivenName).
			Str("machine-key", update.MachineKey.ShortString())
	}

	if err = api.h.db.UpdateNode(
		types.NodeID(request.NodeId),
		request.Namespace,
		update,
		request.AddCapabilities,
		request.DelCapabilities,
	); err != nil {
		logger.Err(err).Msg("Failed to update node")
		return nil, err
	}

	if api.h.cfg.NodeHandler != nil {
		node, err := api.h.db.GetNodeByID(types.NodeID(request.NodeId))
		if err != nil {
			logger.Err(err).Msg("Failed to get node for NodeHandler Update")
			return nil, err
		}
		if _, err := api.h.cfg.NodeHandler.Update(node); err != nil {
			logger.Err(err).Msg("Node handler Update failed")
			return nil, err
		}
	}

	log.Info().
		Str("namespace", request.Namespace).
		Uint64("node-id", request.NodeId).
		Str("name", update.GivenName).
		Str("machine-key", update.MachineKey.ShortString()).
		Msg("Updated node")

	return &v1.UpdateNodeResponse{}, nil
}

func (api headscaleV1APIServer) UpdateNodeShareToUser(
	ctx context.Context,
	request *v1.UpdateNodeShareToUserRequest,
) (*v1.UpdateNodeShareToUserResponse, error) {
	// First check if auth token exists.
	if err := api.auth(ctx, nil); err != nil {
		return nil, err
	}

	node, err := api.h.db.GetNodeByID(types.NodeID(request.NodeId))
	if err != nil {
		return nil, err
	}
	// For modifying would_share_to, check auth against the node owner
	// For modifying accepted_share_to, check auth against if would_be_shared_to
	// has the user listed or the API call is from a namespace admin.
	username := ""
	op := ""
	updatePeers := false
	userNetwork := ""
	logger := log.Error().
		Str("namespace", request.Namespace).
		Uint64("node-id", request.NodeId)
	log.Debug().
		Str("namespace", request.Namespace).
		Uint64("node-id", request.NodeId).
		Str("delete-username", request.GetDelAcceptedShareToUser()).
		Msg("UpdateNodeShareToUser called")
	if request.AddWouldShareToUser != nil || request.DelWouldShareToUser != nil {
		// Allow only one of add/del would_share_to per request
		if request.AddWouldShareToUser != nil && request.DelWouldShareToUser != nil {
			return nil, errors.New("cannot add and delete would_share_to user in the same request")
		}
		s := types.NewAuthScope(node.Namespace, node.User.Name, node.NetworkDomain)
		if err := api.auth(ctx, s); err != nil {
			return nil, err
		}
		if request.AddWouldShareToUser != nil {
			username = *request.AddWouldShareToUser
			op = "add_would_share_to"
		} else if request.DelWouldShareToUser != nil {
			username = *request.DelWouldShareToUser
			op = "delete_would_share_to"
		}
		if username == "" {
			return nil, errors.New("username cannot be empty")
		}
		user, err := api.h.db.GetUserByLoginName(node.Namespace, username)
		if err != nil {
			// TODO: handle the case when user is not yet created
			// TODO: but invite is sent to a future user to share the node.
			if errors.Is(err, db.ErrUserNotFound) {
				if request.DelWouldShareToUser != nil {
					// If we're deleting a user that doesn't exist, we can just ignore it
					return &v1.UpdateNodeShareToUserResponse{}, nil
				}
			}
			return nil, err
		}
		if request.AddWouldShareToUser != nil {
			err = api.h.db.AddWouldShareToUser(node, user)
		} else {
			err = api.h.db.RemoveWouldShareToUser(node, user)
		}
		if err != nil {
			logger.Err(err).Msg("Failed to update node would_share_to")
			return nil, err
		}
	} else if request.AddAcceptedShareToUser != nil || request.DelAcceptedShareToUser != nil {
		// Allow only one of add/del accepted_share_to per request
		if request.AddAcceptedShareToUser != nil && request.DelAcceptedShareToUser != nil {
			return nil, errors.New("cannot add and delete accepted_share_to user in the same request")
		}
		if request.AddAcceptedShareToUser != nil {
			username = *request.AddAcceptedShareToUser
			op = "add_accepted_share_to"
		} else if request.DelAcceptedShareToUser != nil {
			username = *request.DelAcceptedShareToUser
			op = "delete_accepted_share_to"
		}
		if username == "" {
			return nil, errors.New("username cannot be empty")
		}
		// Check if the auth has authorization to operate on the username.
		user, err := api.h.db.GetUserByLoginName(node.Namespace, username)
		if err != nil {
			if errors.Is(err, db.ErrUserNotFound) {
				if op == "delete_accepted_share_to" {
					// Ignore user not found error when deleting accepted_share_to
					log.Debug().
						Str("namespace", request.Namespace).
						Uint64("node-id", request.NodeId).
						Str("username", username).
						Msg("User not found when deleting accepted_share_to, ignoring")
					return &v1.UpdateNodeShareToUserResponse{}, nil
				}
			}
			return nil, err
		}
		s := types.NewAuthScope(node.Namespace, username, user.Network)
		if err := api.auth(ctx, s); err != nil {
			return nil, err
		}
		if request.AddAcceptedShareToUser != nil {
			// Check if the user is already in the accepted_share_to relationship
			isAlreadyAccepted := false
			for _, acceptedUser := range node.AcceptedShareTo {
				if acceptedUser.ID == user.ID {
					isAlreadyAccepted = true
					break
				}
			}

			// Skip if already accepted
			if isAlreadyAccepted {
				log.Info().
					Str("username", username).
					Msg("User already in accepted_share_to, skipping")
			} else {
				// Check if the user is in the would_share_to relationship
				isInWouldShareTo := false
				for _, wouldShareUser := range node.WouldShareTo {
					if wouldShareUser.ID == user.ID {
						isInWouldShareTo = true
						break
					}
				}
				if !isInWouldShareTo {
					s := types.NewAuthScope(node.Namespace, "", "")
					if err := api.auth(ctx, s); err != nil {
						return nil, errors.New("user is not in the would_share_to list of this node")
					}
					// Fall through:
					// Namespace admin can just add a user to share without
					// setting up the would_share_to relationship
				}

				err = api.h.db.AddAcceptedShareToUser(node, user)
				if err != nil {
					logger.Err(err).Msg("Failed to update node accepted_share_to")
					return nil, err
				}
				log.Info().
					Str("namespace", request.Namespace).
					Uint64("node-id", request.NodeId).
					Str("username", username).
					Str("operation", op).
					Msg("Updated")
			}
		} else {
			err = api.h.db.RemoveAcceptedShareToUser(node, user)
			if err != nil {
				logger.Err(err).Msg("Failed to update node accepted_share_to")
				return nil, err
			}
		}
		updatePeers = true
		userNetwork = user.Network
	}

	log.Info().
		Str("namespace", request.Namespace).
		Uint64("node-id", request.NodeId).
		Str("username", username).
		Str("operation", op).
		Msg("Updated. Notifying peers")

	// TODO: notify only the node being shared and the user add or removed.
	if updatePeers {
		if err := api.h.mapper.NotifyPeers(
			types.StateUpdate{
				Type:          types.StateFullUpdate,
				Message:       "Node peers update due to sharing change",
				Namespace:     node.Namespace,
				NetworkDomain: node.NetworkDomain,
			},
		); err != nil {
			logger.Err(err).Msg("Failed to update node peers")
			return nil, err
		}
		if err := api.h.mapper.NotifyPeers(
			types.StateUpdate{
				Type:          types.StateFullUpdate,
				Message:       "User peers update due to sharing change",
				Namespace:     node.Namespace,
				NetworkDomain: userNetwork,
			},
		); err != nil {
			logger.Err(err).Msg("Failed to update user nodes' peers")
			return nil, err
		}
	}

	return &v1.UpdateNodeShareToUserResponse{}, nil
}

func (api headscaleV1APIServer) UpdateUserNetworkDomain(
	ctx context.Context,
	request *v1.UpdateUserNetworkDomainRequest,
) (*v1.UpdateUserNetworkDomainResponse, error) {
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}

	logger := log.Error().
		Str("namespace", request.Namespace).
		Str("user", request.User).
		Str("network-domain", request.Network)

	if err := api.h.db.UpdateUserNetworkDomain(
		request.User,
		request.Network,
	); err != nil {
		logger.Err(err).Msg("Failed to update user")
		return nil, err
	}

	log.Info().
		Str("namespace", request.Namespace).
		Str("user", request.User).
		Str("network-domain", request.Network).
		Msg("Updated user network domain")

	return &v1.UpdateUserNetworkDomainResponse{}, nil
}

func (api headscaleV1APIServer) UpdateUserPeers(
	ctx context.Context,
	request *v1.UpdateUserPeersRequest,
) (*v1.UpdateUserPeersResponse, error) {
	if err := api.auth(ctx, request); err != nil {
		return nil, err
	}
	user, err := api.h.db.GetUser(request.User)
	if err != nil {
		return nil, err
	}

	namespace := ""
	if user.Namespace != nil {
		namespace = *user.Namespace
	}
	logger := log.Error().
		Str("namespace", request.Namespace).
		Str("user", request.User)

	if err := api.h.mapper.NotifyPeers(
		types.StateUpdate{
			Type:          types.StateFullUpdate,
			Message:       "User peers update requested via API",
			Namespace:     namespace,
			NetworkDomain: user.Network,
		},
	); err != nil {
		logger.Err(err).Msg("Failed to update user peers")
		return nil, err
	}

	log.Info().
		Str("namespace", request.Namespace).
		Str("user", request.User).
		Msg("Updated user peers")

	return &v1.UpdateUserPeersResponse{}, nil
}

// __END_CYLONIX_MOD__
