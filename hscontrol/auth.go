package hscontrol

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db" // __CYLONIX_ADD__
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	// __CYLONIX_REMOVED__ "tailscale.com/control/controlclient" no longer used after v0.28 merge
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

type AuthProvider interface {
	RegisterHandler(http.ResponseWriter, *http.Request)
	AuthURL(types.RegistrationID) string
}

// __BEGIN_CYLONIX_ADD__
// logAuthFunc produces three log helpers (info/trace/error) pre-populated
// with common cylonix fields (namespace, machine/node key, hostname, ...).
// It is kept for use by cylonix-specific register paths (AuthKey/OIDC).
func logAuthFunc(
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (func(string), func(string), func(error, string)) {
	return func(msg string) {
			log.Info().
				Caller(1).
				Str("namespace", req.Header.Get("namespace")).
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Msg(msg)
		},
		func(msg string) {
			log.Trace().
				Caller(1).
				Str("namespace", req.Header.Get("namespace")).
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Msg(msg)
		},
		func(err error, msg string) {
			log.Error().
				Caller(1).
				Str("namespace", req.Header.Get("namespace")).
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Err(err).
				Msg(msg)
		}
}

// postRegistrationHandling performs common tasks after a node has been
// registered through any path (auth-key, OIDC, gRPC/CLI). In v0.28 upstream
// route persistence/auto-approval has moved into the state package; this
// stub is kept so cylonix call sites continue to compile and serve as a
// hook point for future cylonix-specific post-registration logic.
func (h *Headscale) postRegistrationHandling(node *types.Node) {
	if node == nil {
		return
	}
	// Route persistence and auto-approval handled by state.AutoApproveRoutes
	// after HandleNodeFromAuthPath / HandleNodeFromPreAuthKey.
}

// __END_CYLONIX_ADD__

// handleRegister is the logic for registering a client.
func (h *Headscale) handleRegister(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Check for logout/expiry FIRST, before checking auth key.
	// Tailscale clients may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry takes precedence - it's a logout regardless of other fields.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		log.Debug().
			Str("node.key", req.NodeKey.ShortString()).
			Time("expiry", req.Expiry).
			Bool("has_auth", req.Auth != nil).
			Msg("Detected logout attempt with past expiry")

		// This is a logout attempt (expiry in the past)
		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			log.Debug().
				Uint64("node.id", node.ID().Uint64()).
				Str("node.name", node.Hostname()).
				Bool("is_ephemeral", node.IsEphemeral()).
				Bool("has_authkey", node.AuthKey().Valid()).
				Msg("Found existing node for logout, calling handleLogout")

			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling logout: %w", err)
			}
			if resp != nil {
				return resp, nil
			}
		} else {
			log.Warn().
				Str("node.key", req.NodeKey.ShortString()).
				Msg("Logout attempt but node not found in NodeStore")
		}
	}

	// If the register request does not contain a Auth struct, it means we are logging
	// out an existing node (legacy logout path for clients that send Auth=nil).
	if req.Auth == nil {
		// If the register request present a NodeKey that is currently in use, we will
		// check if the node needs to be sent to re-auth, or if the node is logging out.
		// We do not look up nodes by [key.MachinePublic] as it might belong to multiple
		// nodes, separated by users and this path is handling expiring/logout paths.
		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			// When tailscaled restarts, it sends RegisterRequest with Auth=nil and Expiry=zero.
			// Return the current node state without modification.
			// See: https://github.com/juanfont/headscale/issues/2862
			if req.Expiry.IsZero() && node.Expiry().Valid() && !node.IsExpired() {
				return nodeToRegisterResponse(node, h.cfg), nil
			}

			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling existing node: %w", err)
			}

			// If resp is not nil, we have a response to return to the node.
			// If resp is nil, we should proceed and see if the node is trying to re-auth.
			if resp != nil {
				return resp, nil
			}
		} else {
			// If the register request is not attempting to register a node, and
			// we cannot match it with an existing node, we consider that unexpected
			// as only register nodes should attempt to log out.
			log.Debug().
				Str("node.key", req.NodeKey.ShortString()).
				Str("machine.key", machineKey.ShortString()).
				Bool("unexpected", true).
				Msg("received register request with no auth, and no existing node")
		}
	}

	// If the [tailcfg.RegisterRequest] has a Followup URL, it means that the
	// node has already started the registration process and we should wait for
	// it to finish the original registration.
	if req.Followup != "" {
		return h.waitForFollowup(ctx, req, machineKey)
	}

	// Pre authenticated keys are handled slightly different than interactive
	// logins as they can be done fully sync and we can respond to the node with
	// the result as it is waiting.
	if isAuthKey(req) {
		resp, err := h.handleRegisterWithAuthKey(req, machineKey)
		if err != nil {
			// Preserve HTTPError types so they can be handled properly by the HTTP layer
			var httpErr HTTPError
			if errors.As(err, &httpErr) {
				return nil, httpErr
			}

			return nil, fmt.Errorf("handling register with auth key: %w", err)
		}

		return resp, nil
	}

	resp, err := h.handleRegisterInteractive(req, machineKey)
	if err != nil {
		return nil, fmt.Errorf("handling register interactive: %w", err)
	}

	return resp, nil
}

// handleLogout checks if the [tailcfg.RegisterRequest] is a
// logout attempt from a node. If the node is not attempting to
func (h *Headscale) handleLogout(
	node types.NodeView,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Fail closed if it looks like this is an attempt to modify a node where
	// the node key and the machine key the noise session was started with does
	// not align.
	if node.MachineKey() != machineKey {
		return nil, NewHTTPError(http.StatusUnauthorized, "node exist with different machine key", nil)
	}

	// Note: We do NOT return early if req.Auth is set, because Tailscale clients
	// may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry indicates logout, regardless of whether Auth is present.
	// The expiry check below will handle the logout logic.

	// If the node is expired and this is not a re-authentication attempt,
	// force the client to re-authenticate.
	// TODO(kradalby): I wonder if this is a path we ever hit?
	if node.IsExpired() {
		log.Trace().Str("node.name", node.Hostname()).
			Uint64("node.id", node.ID().Uint64()).
			Interface("reg.req", req).
			Bool("unexpected", true).
			Msg("Node key expired, forcing re-authentication")
		return &tailcfg.RegisterResponse{
			NodeKeyExpired:    true,
			MachineAuthorized: false,
			AuthURL:           "", // Client will need to re-authenticate
		}, nil
	}

	// If we get here, the node is not currently expired, and not trying to
	// do an auth.
	// The node is likely logging out, but before we run that logic, we will validate
	// that the node is not attempting to tamper/extend their expiry.
	// If it is not, we will expire the node or in the case of an ephemeral node, delete it.

	// The client is trying to extend their key, this is not allowed.
	if req.Expiry.After(time.Now()) {
		return nil, NewHTTPError(http.StatusBadRequest, "extending key is not allowed", nil)
	}

	// If the request expiry is in the past, we consider it a logout.
	// Zero expiry is handled in handleRegister() before calling this function.
	if req.Expiry.Before(time.Now()) {
		log.Debug().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Bool("is_ephemeral", node.IsEphemeral()).
			Bool("has_authkey", node.AuthKey().Valid()).
			Time("req.expiry", req.Expiry).
			Msg("Processing logout request with past expiry")

		if node.IsEphemeral() {
			log.Info().
				Uint64("node.id", node.ID().Uint64()).
				Str("node.name", node.Hostname()).
				Msg("Deleting ephemeral node during logout")

			c, err := h.state.DeleteNode(node)
			if err != nil {
				return nil, fmt.Errorf("deleting ephemeral node: %w", err)
			}

			h.Change(c)

			return &tailcfg.RegisterResponse{
				NodeKeyExpired:    true,
				MachineAuthorized: false,
			}, nil
		}

		log.Debug().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Msg("Node is not ephemeral, setting expiry instead of deleting")
	}

	// Update the internal state with the nodes new expiry, meaning it is
	// logged out.
	expiry := req.Expiry

	updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), &expiry)
	if err != nil {
		return nil, fmt.Errorf("setting node expiry: %w", err)
	}

	h.Change(c)

	return nodeToRegisterResponse(updatedNode, h.cfg), nil
}

// isAuthKey reports if the register request is a registration request
// using an pre auth key.
func isAuthKey(req tailcfg.RegisterRequest) bool {
	return req.Auth != nil && req.Auth.AuthKey != ""
}

// __CYLONIX_MOD__ Pass cfg through so UserView.TailscaleUser/Login route
// through cylonix's NodeHandler hook (returns email + display_name from
// user_base_infos). Without cfg the cylonix UUID leaks as the LoginName.
func nodeToRegisterResponse(node types.NodeView, cfg *types.Config) *tailcfg.RegisterResponse {
	resp := &tailcfg.RegisterResponse{
		NodeKeyExpired: node.IsExpired(),

		// Headscale does not implement the concept of machine authorization
		// so we always return true here.
		// Revisit this if #2176 gets implemented.
		MachineAuthorized: true,
	}

	// For tagged nodes, use the TaggedDevices special user
	// For user-owned nodes, include User and Login information from the actual user
	if node.IsTagged() {
		resp.User = types.TaggedDevices.View().TailscaleUser(cfg)
		resp.Login = types.TaggedDevices.View().TailscaleLogin(cfg)
	} else if node.Owner().Valid() {
		resp.User = node.Owner().TailscaleUser(cfg)
		resp.Login = node.Owner().TailscaleLogin(cfg)
	}

	return resp
}

func (h *Headscale) waitForFollowup(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// __BEGIN_CYLONIX_ADD__
	// Cylonix flow: when a NodeHandler is wired up, the followup URL is the
	// cylonix-manager UI login form (<base>/login/<sessionID>) — not the
	// upstream <base>/register/<registrationID> form. The cylonix design is
	// poll-and-backoff: server returns the same AuthURL while auth is still
	// pending, client retries; server returns the registered RegisterResponse
	// once NodeHandler.AuthStatus reports the user has completed sign-in.
	if h.cfg.NodeHandler != nil {
		logFn := func(msg string) {
			log.Debug().
				Str("machine_key", machineKey.ShortString()).
				Str("followup", req.Followup).
				Msg(msg)
		}
		node, err := h.checkAuthStatus(nil, machineKey, req, logFn)
		if err != nil {
			return nil, NewHTTPError(http.StatusInternalServerError, "auth status check failed", err)
		}
		if node != nil {
			return nodeToRegisterResponse(node.View(), h.cfg), nil
		}
		// Auth still pending. Do not blindly echo the client-quoted followup
		// URL: re-validate it with the manager via NodeHandler.AuthURL, which
		// returns the same URL while its login session is still valid and
		// mints a fresh one when it is not (expired or cleaned up). The
		// machine's registration cache entry is refreshed with the result so
		// a later fresh register (e.g. after a node key rotation) re-uses the
		// same session (pre-v0.28 behavior).
		authURL, err := h.reissueFollowupAuthURL(req, machineKey, logFn)
		if err != nil {
			return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate auth URL", err)
		}
		return &tailcfg.RegisterResponse{AuthURL: authURL}, nil
	}
	// __END_CYLONIX_ADD__

	fu, err := url.Parse(req.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid followup URL", err)
	}

	followupReg, err := types.RegistrationIDFromString(strings.ReplaceAll(fu.Path, "/register/", ""))
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid registration ID", err)
	}

	if reg, ok := h.state.GetRegistrationCacheEntry(followupReg); ok {
		select {
		case <-ctx.Done():
			return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", err)
		case node := <-reg.Registered:
			if node == nil {
				// registration is expired in the cache, instruct the client to try a new registration
				return h.reqToNewRegisterResponse(req, machineKey)
			}
			return nodeToRegisterResponse(node.View(), h.cfg), nil
		}
	}

	// if the follow-up registration isn't found anymore, instruct the client to try a new registration
	return h.reqToNewRegisterResponse(req, machineKey)
}

// __BEGIN_CYLONIX_ADD__
// reissueFollowupAuthURL revalidates a pending login's auth URL with the
// NodeHandler (cylonix-manager). While the client-quoted session is valid the
// same URL is returned; if the session has expired or been cleaned up a fresh
// one is minted. The machine's registration cache entry is refreshed with the
// request's current node identity and the resulting URL so that a later fresh
// register (e.g. after a node key rotation) re-uses the same login session.
// Restores the pre-v0.28 machine-key-keyed registration cache behavior.
func (h *Headscale) reissueFollowupAuthURL(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	logFn func(string),
) (string, error) {
	regID, ok := h.state.FindRegistrationIDByMachineKey(machineKey)
	var entry *types.RegisterNode
	if ok {
		entry, ok = h.state.GetRegistrationCacheEntry(regID)
	}
	if !ok || entry == nil {
		// No in-flight entry for this machine (e.g. the server restarted):
		// re-create one so the completion path (registerNodeForOIDCCallback)
		// can find it once the user finishes signing in.
		newRegID, err := types.NewRegistrationID()
		if err != nil {
			return "", fmt.Errorf("generating registration ID: %w", err)
		}
		hostname := util.EnsureHostname(
			req.Hostinfo,
			machineKey.String(),
			req.NodeKey.String(),
		)
		hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
		hostinfo.Hostname = hostname
		newEntry := types.NewRegisterNode(types.Node{
			Hostname:   hostname,
			MachineKey: machineKey,
			NodeKey:    req.NodeKey,
			Hostinfo:   hostinfo,
			LastSeen:   ptr.To(time.Now()),
		})
		regID, entry = newRegID, &newEntry
		logFn("re-created registration cache entry for followup")
	}

	// Refresh the in-flight node with the request's current identity so the
	// completion path registers the key the client is actually using.
	entry.Node.NodeKey = req.NodeKey
	if req.Hostinfo != nil {
		entry.Node.Hostinfo = req.Hostinfo
		if req.Hostinfo.Hostname != "" {
			entry.Node.Hostname = req.Hostinfo.Hostname
		}
	}
	entry.Node.LastSeen = ptr.To(time.Now())

	authURL, err := h.resolveAuthURL(&entry.Node, regID, req.Followup)
	if err != nil {
		return "", err
	}
	entry.FollowUp = authURL
	h.state.SetRegistrationCacheEntry(regID, *entry)
	if authURL != req.Followup {
		logFn("followup auth URL replaced: " + authURL)
	}
	return authURL, nil
}

// __END_CYLONIX_ADD__

// reqToNewRegisterResponse refreshes the registration flow by creating a new
// registration ID and returning the corresponding AuthURL so the client can
// restart the authentication process.
func (h *Headscale) reqToNewRegisterResponse(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	newRegID, err := types.NewRegistrationID()
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate registration ID", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo,
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	hostinfo.Hostname = hostname

	nodeToRegister := types.NewRegisterNode(
		types.Node{
			Hostname:   hostname,
			MachineKey: machineKey,
			NodeKey:    req.NodeKey,
			Hostinfo:   hostinfo,
			LastSeen:   ptr.To(time.Now()),
		},
	)

	if !req.Expiry.IsZero() {
		nodeToRegister.Node.Expiry = &req.Expiry
	}

	log.Info().Msgf("New followup node registration using key: %s", newRegID)
	h.state.SetRegistrationCacheEntry(newRegID, nodeToRegister)

	// __BEGIN_CYLONIX_MOD__ Delegate AuthURL via NodeHandler hook (cylonix
	// returns <base>/login/<sessionID>); upstream calls authProvider.AuthURL
	// directly, which would emit /register/<id>.
	authURL, err := h.resolveAuthURL(&nodeToRegister.Node, newRegID, req.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate auth URL", err)
	}
	return &tailcfg.RegisterResponse{AuthURL: authURL}, nil
	// __END_CYLONIX_MOD__
}

// __BEGIN_CYLONIX_ADD__
// resolveAuthURL prefers the cylonix NodeHandler.AuthURL hook (which builds
// a cylonix-manager UI login URL like <base>/login/<sessionID>) when one is
// configured. Without the hook, the upstream AuthProviderWeb /register/<id>
// page is used. Pre-v0.28 cylonix always went through the hook; the merge
// regressed two callers (handleRegisterInteractive + reqToNewRegisterResponse)
// to the bare authProvider.AuthURL path, which is why nodes started seeing
// http://127.0.0.1:8000/register/<id> in their AuthURL responses.
//
// Errors from the hook are surfaced to the caller — silently falling back
// to the default URL would hide misconfigurations (e.g. the cylonix oauth
// state DB being unreachable) and leave the client with a non-functional
// /register/<id> URL the user shouldn't be sent to.
func (h *Headscale) resolveAuthURL(node *types.Node, registrationID types.RegistrationID, currentURL string) (string, error) {
	if h.cfg.NodeHandler != nil {
		return h.cfg.NodeHandler.AuthURL(node, currentURL)
	}
	return h.authProvider.AuthURL(registrationID), nil
}

// __END_CYLONIX_ADD__

func (h *Headscale) handleRegisterWithAuthKey(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	node, changed, err := h.state.HandleNodeFromPreAuthKey(
		req,
		machineKey,
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre auth key", nil)
		}
		var perr types.PAKError
		if errors.As(err, &perr) {
			return nil, NewHTTPError(http.StatusUnauthorized, perr.Error(), nil)
		}

		return nil, err
	}

	// If node is not valid, it means an ephemeral node was deleted during logout
	if !node.Valid() {
		h.Change(changed)
		return nil, nil
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// nodesChangedHook and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	// TODO(kradalby): This needs to be ran as part of the batcher maybe?
	// now since we dont update the node/pol here anymore
	routesChange, err := h.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, fmt.Errorf("auto approving routes: %w", err)
	}

	// Send both changes. Empty changes are ignored by Change().
	h.Change(changed, routesChange)

	// TODO(kradalby): I think this is covered above, but we need to validate that.
	// // If policy changed due to node registration, send a separate policy change
	// if policyChanged {
	// 	policyChange := change.PolicyChange()
	// 	h.Change(policyChange)
	// }

	resp := &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		NodeKeyExpired:    node.IsExpired(),
		User:              node.Owner().TailscaleUser(h.cfg),  // __CYLONIX_MOD__
		Login:             node.Owner().TailscaleLogin(h.cfg), // __CYLONIX_MOD__
	}

	log.Trace().
		Caller().
		Interface("reg.resp", resp).
		Interface("reg.req", req).
		Str("node.name", node.Hostname()).
		Uint64("node.id", node.ID().Uint64()).
		Msg("RegisterResponse")

	return resp, nil
}

func (h *Headscale) handleRegisterInteractive(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	registrationId, err := types.NewRegistrationID()
	if err != nil {
		return nil, fmt.Errorf("generating registration ID: %w", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo,
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	if req.Hostinfo == nil {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with nil hostinfo, generated default hostname")
	} else if req.Hostinfo.Hostname == "" {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with empty hostname, generated default")
	}
	hostinfo.Hostname = hostname

	// __BEGIN_CYLONIX_ADD__
	// If this machine already has an in-flight registration, re-use its login
	// session instead of minting a new one — the client may have rotated its
	// node key after receiving the auth URL (restores pre-v0.28 behavior).
	// NodeHandler.AuthURL validates the remembered session, updates its
	// stored node key, and returns the same URL; if the session is gone a
	// fresh one is minted under the same registration entry.
	if h.cfg.NodeHandler != nil {
		if regID, ok := h.state.FindRegistrationIDByMachineKey(machineKey); ok {
			if entry, ok2 := h.state.GetRegistrationCacheEntry(regID); ok2 {
				entry.Node.NodeKey = req.NodeKey
				entry.Node.Hostname = hostname
				entry.Node.Hostinfo = hostinfo
				entry.Node.LastSeen = ptr.To(time.Now())
				if !req.Expiry.IsZero() {
					entry.Node.Expiry = &req.Expiry
				}
				authURL, err := h.resolveAuthURL(&entry.Node, regID, entry.FollowUp)
				if err == nil {
					entry.FollowUp = authURL
					h.state.SetRegistrationCacheEntry(regID, *entry)
					log.Info().
						Str("machine.key", machineKey.ShortString()).
						Str("node.key", req.NodeKey.ShortString()).
						Msgf("Re-using in-flight registration %s (node key may have rotated)", regID)
					return &tailcfg.RegisterResponse{AuthURL: authURL}, nil
				}
				log.Warn().
					Err(err).
					Str("machine.key", machineKey.ShortString()).
					Str("node.key", req.NodeKey.ShortString()).
					Msg("Failed to re-use in-flight registration; starting a new one")
			}
		}
	}
	// __END_CYLONIX_ADD__

	nodeToRegister := types.NewRegisterNode(
		types.Node{
			Hostname:   hostname,
			MachineKey: machineKey,
			NodeKey:    req.NodeKey,
			Hostinfo:   hostinfo,
			LastSeen:   ptr.To(time.Now()),
		},
	)

	if !req.Expiry.IsZero() {
		nodeToRegister.Node.Expiry = &req.Expiry
	}

	h.state.SetRegistrationCacheEntry(
		registrationId,
		nodeToRegister,
	)

	log.Info().Msgf("Starting node registration using key: %s", registrationId)

	// __BEGIN_CYLONIX_MOD__ Delegate AuthURL via NodeHandler hook.
	authURL, err := h.resolveAuthURL(&nodeToRegister.Node, registrationId, req.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate auth URL", err)
	}
	// Remember the issued URL so fresh registers from this machine (e.g.
	// after a node key rotation) re-use the same login session.
	nodeToRegister.FollowUp = authURL
	h.state.SetRegistrationCacheEntry(registrationId, nodeToRegister)
	return &tailcfg.RegisterResponse{AuthURL: authURL}, nil
	// __END_CYLONIX_MOD__
}

// __BEGIN_CYLONIX_MOD__
func writeInternalError(writer http.ResponseWriter, err error) {
	http.Error(writer, "Internal server error: "+err.Error(), http.StatusInternalServerError)
}
func logNodeError(node *types.Node, err error, msg string) {
	// __BEGIN_CYLONIX_MOD__ node.ErrorLog was removed in v0.28; inline the equivalent fields.
	log.Error().
		Caller().
		Str("node", node.Hostname).
		Str("namespace", node.Namespace).
		Uint64("id", uint64(node.ID)).
		Str("machine_key", node.MachineKey.ShortString()).
		Str("node_key", node.NodeKey.ShortString()).
		Err(err).
		Msg(msg)
	// __END_CYLONIX_MOD__
}

func (h *Headscale) refreshNodeKeyAndExpiry(node *types.Node, newKey key.NodePublic, oldKey key.NodePublic, newExpiry *time.Time) error {
	log.Info().
		Str("user", node.User.Name).
		Str("namespace", node.Namespace).
		Str("machine", node.MachineKey.ShortString()).
		Str("node", node.Hostname).
		Uint64("node_id", node.ID.Uint64()).
		Bool("refresh_expiry", newExpiry != nil).
		Str("node_key", node.NodeKey.ShortString()).
		Str("new_node_key", newKey.ShortString()).
		Str("old_node_key", oldKey.ShortString()).
		Msg("node key and expiry refresh")

	if h.cfg.NodeHandler != nil {
		if err := h.cfg.NodeHandler.RotateNodeKey(node, newKey); err != nil {
			logNodeError(node, err, "failed to rotate node key")
			return err
		}
	}

	// __BEGIN_CYLONIX_MOD__ h.db is gone in v0.28; route through state.DB().
	err := h.state.DB().Write(func(tx *gorm.DB) error {
		return db.NodeSetNodeKey(tx, node, newKey)
	})
	if err != nil {
		logNodeError(node, err, "failed to update node key in the database")
		return err
	}
	// Also refresh the in-memory NodeStore so subsequent NoisePollNetMap
	// lookups by the new node_key succeed. db.NodeSetNodeKey only writes
	// the headscale `nodes` row; without this update the NodeStore index
	// nodesByNodeKey still maps the OLD key, and the noise poll endpoint
	// returns 404 for the rotated client.
	//
	// The expiry MUST be updated here too: the netmap (and thus the self
	// node's KeyExpiry the client renders) is built from the NodeStore
	// NodeView, not the DB row. Updating only the DB (NodeSetExpiry below)
	// left the NodeStore — and so the netmap — with the OLD expiry, so after
	// reauth the client kept warning "key expires in N days" forever even
	// though the admin UI (which reads the DB) showed the new expiry.
	if _, ok := h.state.UpdateNode(node.ID, func(n *types.Node) {
		n.NodeKey = newKey
		if newExpiry != nil {
			e := *newExpiry
			n.Expiry = &e
		}
	}); !ok {
		log.Warn().
			Uint64("node.id", node.ID.Uint64()).
			Str("new_node_key", newKey.ShortString()).
			Msg("NodeStore update after key rotation failed: node not in store")
	}
	if newExpiry != nil {
		err = h.state.DB().NodeSetExpiry(node.ID, *newExpiry)
		if err != nil {
			logNodeError(node, err, "failed to update expiry in the database")
			return err
		}
	}
	// __END_CYLONIX_MOD__
	return nil
}

func (h *Headscale) checkAuthStatus(
	writer http.ResponseWriter, machineKey key.MachinePublic,
	regReq tailcfg.RegisterRequest, logInfo func(string),
) (*types.Node, error) {
	if h.cfg.NodeHandler == nil {
		logInfo("NodeHandler is not configured, skipping auth status check")
		return nil, nil
	}
	followup := regReq.Followup
	nodeKey := regReq.NodeKey

	userStableID, err := h.cfg.NodeHandler.AuthStatus(followup)
	if err != nil {
		logInfo("Failed to get auth status: " + err.Error())
		return nil, nil
	}
	if userStableID == "" {
		//logInfo("User not logged in yet url=" + followup)
		// Not yet approved. Force the client to wait.
		return nil, nil
	}
	// __BEGIN_CYLONIX_MOD__ all h.db lookups go through h.state.DB() now.
	user, err := h.state.DB().GetUser(userStableID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	logInfo("User logged in " + userStableID)
	expiry := time.Now().Add(time.Hour * 24 * 150)

	// Check if the node is already registered
	node, err := h.state.DB().GetNodeByUserAndMachineKey(user.ID, machineKey)
	if !nodeKey.IsZero() {
		nodeByKey, _ := h.state.DB().GetNodeByNodeKey(nodeKey)
		if nodeByKey != nil {
			if node != nil && nodeByKey.ID != node.ID {
				return nil, fmt.Errorf("node key conflict: nodeKey belongs to a different node")
			}
			if node == nil && (nodeByKey.UserID == nil || *nodeByKey.UserID != user.ID) { // __CYLONIX_MOD__ UserID is now *uint
				return nil, fmt.Errorf("node key conflict: nodeKey belongs to a different user")
			}
			if node == nil {
				node = nodeByKey
				err = nil
			}
		}
	}
	// __END_CYLONIX_MOD__
	if err == nil {
		logInfo("Node already registered")
		err = h.refreshNodeKeyAndExpiry(node, nodeKey, key.NodePublic{}, &expiry)
		// __CYLONIX_REMOVED__ h.registrationCache.Delete(machineKey.String()) — v0.28 cache is keyed
		// by types.RegistrationID rather than MachinePublic; the OIDC followup path now
		// performs cache cleanup inside state.HandleNodeFromAuthPath, so the explicit
		// delete-by-machine-key here is no longer reachable. The original behaviour was
		// "drop the in-flight registration entry once the node finishes auth".
		logInfo("Node registered after logged in.")
		if err != nil {
			return nil, fmt.Errorf("failed to refresh node key and/or expiry: %w", err)
		}
		h.postRegistrationHandling(node) // __CYLONIX_ADD__ save routes on re-auth
	} else {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			// __CYLONIX_REMOVED__ h.registrationCache.Delete(machineKey.String()) — see note above.
			return nil, fmt.Errorf("failed to get node before authorization: %w", err)
		}

		// __BEGIN_CYLONIX_ADD__
		// Delegate to the cylonix wrapper which now uses
		// state.FindRegistrationIDByMachineKey + HandleNodeFromAuthPath to
		// complete the registration. Errors here are logged but not surfaced
		// to the caller because the registration may have already been
		// finalised by the upstream AuthProviderOIDC handler.
		if err := h.registerNodeForOIDCCallback(writer, user, &machineKey, expiry); err != nil {
			logInfo("registerNodeForOIDCCallback failed: " + err.Error())
		} else {
			logInfo("Node registered for OIDC callback.")
		}
		// __END_CYLONIX_ADD__
	}

	// __BEGIN_CYLONIX_MOD__
	node, err = h.state.DB().GetNodeByNodeKey(nodeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get node after authorization: %w", err)
	}
	logInfo("Node registered after authorization")
	// __CYLONIX_REMOVED__ h.handleNodeWithValidRegistration(writer, *node, machineKey) — this helper
	// did not survive the v0.28 merge (the upstream noise/auth path no longer routes through a
	// per-machine handshake response writer here). The state package now finalises registration
	// inline via HandleNodeFromAuthPath; no replacement call is needed.
	// __END_CYLONIX_MOD__
	return node, nil
}

// __END_CYLONIX_MOD__
