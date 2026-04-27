package hscontrol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

const (
	keepAliveInterval = 50 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context
	capVer tailcfg.CapabilityVersion

	cancelChMu deadlock.Mutex

	ch           chan *tailcfg.MapResponse
	cancelCh     chan struct{}
	cancelChOpen bool

	keepAlive       time.Duration
	keepAliveTicker *time.Ticker

	node *types.Node
	w    http.ResponseWriter
}

func (h *Headscale) newMapSession(
	ctx context.Context,
	req tailcfg.MapRequest,
	w http.ResponseWriter,
	node *types.Node,
) *mapSession {
	// Cylonix hostname/cap-version syncing used to happen here via
	// h.db.MaybeUpdateNodeGivenName / MaybeUpdateNodeCapVersion; in v0.28
	// those semantics moved into state.UpdateNodeFromMapRequest invoked by
	// serve()/serveLongPoll().
	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond)

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		ch:           make(chan *tailcfg.MapResponse, h.cfg.Tuning.NodeMapSessionBufferedChanSize),
		cancelCh:     make(chan struct{}),
		cancelChOpen: true,

		keepAlive:       ka,
		keepAliveTicker: nil,
	}
}

func (m *mapSession) isStreaming() bool {
	return m.req.Stream
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers
}

func (m *mapSession) resetKeepAlive() {
	m.keepAliveTicker.Reset(m.keepAlive)
}

func (m *mapSession) beforeServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Cancel(m.node.ID)
	}
}

// afterServeLongPoll is called when a long-polling session ends and the node
// is disconnected.
func (m *mapSession) afterServeLongPoll() {
	if m.node != nil && m.node.IsEphemeral() { // __CYLONIX_MOD__
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.EphemeralNodeInactivityTimeout)
	}
}

// serve handles non-streaming requests.
func (m *mapSession) serve() {
	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// Process the MapRequest to update node state (endpoints, hostinfo, etc.)
	c, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		httpError(m.w, err)
		return
	}

	m.h.Change(c)

	// If OmitPeers is true and Stream is false
	// then the server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// This is what Tailscale calls a Lite update, the client ignores
	// the response and just wants a 200.
	// !req.stream && req.OmitPeers
	if m.isEndpointUpdate() {
		m.w.WriteHeader(http.StatusOK)
		mapResponseEndpointUpdates.WithLabelValues("ok").Inc()
	}
}

// serveLongPoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
func (m *mapSession) serveLongPoll() {
	m.beforeServeLongPoll()

	log.Trace().Caller().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Msg("Long poll session started because client connected")

	// Clean up the session when the client disconnects
	defer func() {
		m.cancelChMu.Lock()
		m.cancelChOpen = false
		close(m.cancelCh)
		m.cancelChMu.Unlock()

		_ = m.h.mapBatcher.RemoveNode(m.node.ID, m.ch)

		// When a node disconnects, it might rapidly reconnect (e.g. mobile clients, network weather).
		// Instead of immediately marking the node as offline, we wait a few seconds to see if it reconnects.
		// If it does reconnect, the existing mapSession will be replaced and the node remains online.
		// If it doesn't reconnect within the timeout, we mark it as offline.
		//
		// This avoids flapping nodes in the UI and unnecessary churn in the network.
		// This is not my favourite solution, but it kind of works in our eventually consistent world.
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		disconnected := true
		// Wait up to 10 seconds for the node to reconnect.
		// 10 seconds was arbitrary chosen as a reasonable time to reconnect.
		for range 10 {
			if m.h.mapBatcher.IsConnected(m.node.ID) {
				disconnected = false
				break
			}
			<-ticker.C
		}

		if disconnected {
			disconnectChanges, err := m.h.state.Disconnect(m.node.ID)
			if err != nil {
				m.errf(err, "Failed to disconnect node %s", m.node.Hostname)
			}

			m.h.Change(disconnectChanges...)
			m.afterServeLongPoll()
			m.infof("node has disconnected, mapSession: %p, chan: %p", m, m.ch)
		}
	}()

	// Set up the client stream
	m.h.clientStreamsOpen.Add(1)
	defer m.h.clientStreamsOpen.Done()

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	// Process the initial MapRequest to update node state (endpoints, hostinfo, etc.)
	// This must be done BEFORE calling Connect() to ensure routes are properly synchronized.
	// When nodes reconnect, they send their hostinfo with announced routes in the MapRequest.
	// We need this data in NodeStore before Connect() sets up the primary routes, because
	// SubnetRoutes() calculates the intersection of announced and approved routes. If we
	// call Connect() first, SubnetRoutes() returns empty (no announced routes yet), causing
	// the node to be incorrectly removed from AvailableRoutes.
	mapReqChange, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		m.errf(err, "failed to update node from initial MapRequest")
		return
	}

	// Connect the node after its state has been updated.
	// We send two separate change notifications because these are distinct operations:
	// 1. UpdateNodeFromMapRequest: processes the client's reported state (routes, endpoints, hostinfo)
	// 2. Connect: marks the node online and recalculates primary routes based on the updated state
	// While this results in two notifications, it ensures route data is synchronized before
	// primary route selection occurs, which is critical for proper HA subnet router failover.
	connectChanges := m.h.state.Connect(m.node.ID)

	m.infof("node has connected, mapSession: %p, chan: %p", m, m.ch)

	// TODO(kradalby): Redo the comments here
	// Add node to batcher so it can receive updates,
	// adding this before connecting it to the state ensure that
	// it does not miss any updates that might be sent in the split
	// time between the node connecting and the batcher being ready.
	if err := m.h.mapBatcher.AddNode(m.node.ID, m.ch, m.capVer); err != nil {
		m.errf(err, "failed to add node to batcher")
		log.Error().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Err(err).Msg("AddNode failed in poll session")
		return
	}
	log.Debug().Caller().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Msg("AddNode succeeded in poll session because node added to batcher")

	m.h.Change(mapReqChange)
	m.h.Change(connectChanges...)

	// Loop through updates and continuously send them to the
	// client.
	for {
		// consume channels with update, keep alives or "batch" blocking signals
		select {
		case <-m.cancelCh:
			m.tracef("poll cancelled received")
			mapResponseEnded.WithLabelValues("cancelled").Inc()
			return

		case <-ctx.Done():
			m.tracef("poll context done chan:%p", m.ch)
			mapResponseEnded.WithLabelValues("done").Inc()
			return

		// Consume updates sent to node
		case update, ok := <-m.ch:
			m.tracef("received update from channel, ok: %t", ok)
			if !ok {
				m.tracef("update channel closed, streaming session is likely being replaced")
				return
			}

			if err := m.writeMap(update); err != nil {
				m.errf(err, "cannot write update to client")
				return
			}

			m.tracef("update sent")
			m.resetKeepAlive()

		case <-m.keepAliveTicker.C:
			if err := m.writeMap(&keepAlive); err != nil {
				m.errf(err, "cannot write keep alive")
				return
			}

			if debugHighCardinalityMetrics {
				mapResponseLastSentSeconds.WithLabelValues("keepalive", m.node.ID.String()).Set(float64(time.Now().Unix()))
			}
			mapResponseSent.WithLabelValues("ok", "keepalive").Inc()
			m.resetKeepAlive()
		}
	}
}

// writeMap writes the map response to the client.
// It handles compression if requested and any headers that need to be set.
// It also handles flushing the response if the ResponseWriter
// implements http.Flusher.
func (m *mapSession) writeMap(msg *tailcfg.MapResponse) error {
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling map response: %w", err)
	}

	if m.req.Compress == util.ZstdCompression {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize)
	//nolint:gosec // G115: JSON response size will not exceed uint32 max
	binary.LittleEndian.PutUint32(data, uint32(len(jsonBody)))
	data = append(data, jsonBody...)

	startWrite := time.Now()

/* __BEGIN_CYLONIX_LEGACY_REMOVED__
   The cylonix pollFailoverRoutes / handleEndpointUpdate / handleSaveNode
   helpers below depended on removed v0.28 APIs (h.nodeNotifier,
   h.db.SaveNodeRoutes, h.db.EnableAutoApprovedRoutes, types.StateUpdate
   fan-out). Their responsibilities have moved into
   state.UpdateNodeFromMapRequest / state.AutoApproveRoutes and the
   mapBatcher. The original source is preserved as a comment below.

func (m *mapSession) handleEndpointUpdate_legacy() {
	m.tracef("received endpoint update")

	change := m.node.PeerChangeFromMapRequest(m.req)

	online := m.h.nodeNotifier.IsLikelyConnected(m.node.ID)
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	sendUpdate, routesChanged := hostInfoChanged(m.node.Hostinfo, m.req.Hostinfo)

	// The node might not set NetInfo if it has not changed and if
	// the full HostInfo object is overrwritten, the information is lost.
	// If there is no NetInfo, keep the previous one.
	// From 1.66 the client only sends it if changed:
	// https://github.com/tailscale/tailscale/commit/e1011f138737286ecf5123ff887a7a5800d129a2
	// TODO(kradalby): evaulate if we need better comparing of hostinfo
	// before we take the changes.
	if m.req.Hostinfo.NetInfo == nil {
		m.req.Hostinfo.NetInfo = m.node.Hostinfo.NetInfo
	}
	m.node.Hostinfo = m.req.Hostinfo

	logTracePeerChange(m.node.Hostname, sendUpdate, &change)

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(change) && !sendUpdate {
		mapResponseEndpointUpdates.WithLabelValues("noop").Inc()
		return
	}

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		var err error
		_, err = m.h.db.SaveNodeRoutes(m.node)
		if err != nil {
			m.errf(err, "Error processing node routes")
			http.Error(m.w, "", http.StatusInternalServerError)
			mapResponseEndpointUpdates.WithLabelValues("error").Inc()

			return
		}

		// __BEGIN_CYLONIX_MOD__
		pol, err := m.h.ACLPolicy(&m.node.Namespace, &m.node.NetworkDomain)
		if err != nil {
			m.errf(err, "Could not get ACL policy")
			return
		}
		// __END_CYLONIX_MOD__

		if pol != nil {
			// update routes with peer information
			err := m.h.db.EnableAutoApprovedRoutes(pol, m.node)
			if err != nil {
				m.errf(err, "Error running auto approved routes")
				mapResponseEndpointUpdates.WithLabelValues("error").Inc()
			}
		}

		// Send an update to the node itself with to ensure it
		// has an updated packetfilter allowing the new route
		// if it is defined in the ACL.
		ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-self-hostinfochange", m.node.Hostname)
		m.h.nodeNotifier.NotifyByNodeID(
			ctx,
			types.StateUpdate{
				Type:        types.StateSelfUpdate,
				ChangeNodes: []types.NodeID{m.node.ID},

				Namespace:     m.node.Namespace,     // __CYLONIX_ADD__
				NetworkDomain: m.node.NetworkDomain, // __CYLONIX_ADD__
			},
			m.node.ID)
	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		m.errf(err, "Failed to persist/update node in the database")
		http.Error(m.w, "", http.StatusInternalServerError)
		mapResponseEndpointUpdates.WithLabelValues("error").Inc()

		return
	}

	ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-peers-patch", m.node.Hostname)
	m.h.nodeNotifier.NotifyWithIgnore(
		ctx,
		types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: []types.NodeID{m.node.ID},
			Message:     "called from handlePoll -> update",

			Namespace:     m.node.Namespace,     // __CYLONIX_ADD__
			NetworkDomain: m.node.NetworkDomain, // __CYLONIX_ADD__
		},
		m.node.ID)

	m.w.WriteHeader(http.StatusOK)
	mapResponseEndpointUpdates.WithLabelValues("ok").Inc()

	return
}

// handleSaveNode saves node updates in the maprequest _streaming_
// path and is mostly the same code as in handleEndpointUpdate.
// It is not attempted to be deduplicated since it will go away
// when we stop supporting older than 68 which removes updates
// when the node is streaming.
func (m *mapSession) handleSaveNode() error {
	m.tracef("saving node update from stream session")

	change := m.node.PeerChangeFromMapRequest(m.req)

	// A stream is being set up, the node is Online
	online := true
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	sendUpdate, routesChanged := hostInfoChanged(m.node.Hostinfo, m.req.Hostinfo)
	m.node.Hostinfo = m.req.Hostinfo

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(change) || !sendUpdate {
		return nil
	}

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		var err error
		_, err = m.h.db.SaveNodeRoutes(m.node)
		if err != nil {
			return err
		}

		// __BEGIN_CYLONIX_MOD__
		pol, err := m.h.ACLPolicy(&m.node.Namespace, &m.node.NetworkDomain)
		if err != nil {
			m.errf(err, "Could not get ACL policy")
			return err
		}
		// __END_CYLONIX_MOD__

		if pol != nil {
			// update routes with peer information
			err := m.h.db.EnableAutoApprovedRoutes(pol, m.node)
			if err != nil {
				return err
			}
		}
	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		return err
	}

	ctx := types.NotifyCtx(context.Background(), "pre-68-update-while-stream", m.node.Hostname)
	m.h.nodeNotifier.NotifyWithIgnore(
		ctx,
		types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: []types.NodeID{m.node.ID},
			Message:     "called from handlePoll -> pre-68-update-while-stream",

			Namespace:     m.node.Namespace,
			NetworkDomain: m.node.NetworkDomain,
		},
		m.node.ID)
*/
// __END_CYLONIX_LEGACY_REMOVED__

	_, err = m.w.Write(data)
	if err != nil {
		return err
	}

	if m.isStreaming() {
		if f, ok := m.w.(http.Flusher); ok {
			f.Flush()
		} else {
			m.errf(nil, "ResponseWriter does not implement http.Flusher, cannot flush")
		}
	}

	log.Trace().
		Caller().
		Str("node.name", m.node.Hostname).
		Uint64("node.id", m.node.ID.Uint64()).
		Str("chan", fmt.Sprintf("%p", m.ch)).
		TimeDiff("timeSpent", time.Now(), startWrite).
		Str("machine.key", m.node.MachineKey.String()).
		Bool("keepalive", msg.KeepAlive).
		Msgf("finished writing mapresp to node chan(%p)", m.ch)

	return nil
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}

// logf adds common mapSession context to a zerolog event.
func (m *mapSession) logf(event *zerolog.Event) *zerolog.Event {
	return event.
		Bool("omitPeers", m.req.OmitPeers).
		Bool("stream", m.req.Stream).
		Uint64("node.id", m.node.ID.Uint64()).
		Str("node.name", m.node.Hostname)
}

//nolint:zerologlint // logf returns *zerolog.Event which is properly terminated with Msgf
func (m *mapSession) infof(msg string, a ...any) { m.logf(log.Info().Caller()).Msgf(msg, a...) }

//nolint:zerologlint // logf returns *zerolog.Event which is properly terminated with Msgf
func (m *mapSession) tracef(msg string, a ...any) { m.logf(log.Trace().Caller()).Msgf(msg, a...) }

//nolint:zerologlint // logf returns *zerolog.Event which is properly terminated with Msgf
func (m *mapSession) errf(err error, msg string, a ...any) {
	m.logf(log.Error().Caller()).Err(err).Msgf(msg, a...)
}
