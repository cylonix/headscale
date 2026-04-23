package hscontrol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"gorm.io/gorm"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"

	// The first 9 bytes from the server to client over Noise are either an HTTP/2
	// settings frame (a normal HTTP/2 setup) or, as Tailscale added later, an "early payload"
	// header that's also 9 bytes long: 5 bytes (earlyPayloadMagic) followed by 4 bytes
	// of length. Then that many bytes of JSON-encoded tailcfg.EarlyNoise.
	// The early payload is optional. Some servers may not send it... But we do!
	earlyPayloadMagic = "\xff\xff\xffTS"

	// EarlyNoise was added in protocol version 49.
	earlyNoiseCapabilityVersion = 49
)

type noiseServer struct {
	headscale *Headscale

	httpBaseConfig *http.Server
	http2Server    *http2.Server
	conn           *controlbase.Conn
	machineKey     key.MachinePublic
	nodeKey        key.NodePublic

	// EarlyNoise-related stuff
	challenge       key.ChallengePrivate
	protocolVersion int

	// __BEGIN_CYLONIX_ADD__
	namespace     string
	networkDomain string
	// __END_CYLONIX_ADD__
}

// __BEGIN_CYLONIX_MOD__
var (
	quietLogf = logger.RateLimitedFn(log.Printf, 5*time.Minute, 5, 100)
)
// __END_CYLONIX_MOD__

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021.
func (h *Headscale) NoiseUpgradeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise upgrade handler for client %s", req.RemoteAddr)

	upgrade := req.Header.Get("Upgrade")
	if upgrade == "" {
		// This probably means that the user is running Headscale behind an
		// improperly configured reverse proxy. TS2021 requires WebSockets to
		// be passed to Headscale. Let's give them a hint.
		log.Warn().
			Caller().
			Msg("No Upgrade header in TS2021 request. If headscale is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	noiseServer := noiseServer{
		headscale: h,
		challenge: key.NewChallenge(),
	}

	noiseConn, err := controlhttpserver.AcceptHTTP(
		req.Context(),
		writer,
		req,
		*h.noisePrivateKey,
		noiseServer.earlyNoise,
	)
	myKey := h.noisePrivateKey.Public().ShortString()
	if err != nil {
		// __BEGIN_CYLONIX_MOD__
		// Suppress the error due to misconfigurations of the deployment without
		// persisting the server private key. Or we simply have a bad client.
		// Don't let the log flood with this.
		v, _ := json.Marshal(req.Header)
		if strings.Contains(err.Error(), "noise handshake failed: decrypting machine key") {
			quietLogf("Noise upgrade failed: %v. Header=%v myKey=%v", err, string(v), myKey)
			return
		}
		log.Debug().Err(err).Str("request", string(v)).Msg("Noise upgrade failed")
		// Even though noise upgrade failed, the HTTP connection has been
		// hijacked already. Do not write to the writer.
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		// __END_CYLONIX_MOD__

		return
	}

	noiseServer.conn = noiseConn
	noiseServer.machineKey = noiseServer.conn.Peer()
	noiseServer.protocolVersion = noiseServer.conn.ProtocolVersion()

	log.Debug().
		Str("machine-key", noiseServer.machineKey.ShortString()).
		Str("my-key", myKey).
		Msg("Noise connection accepted")

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener
	router := mux.NewRouter()
	router.Use(prometheusMiddleware)

	router.HandleFunc("/machine/register", noiseServer.NoiseRegistrationHandler).
		Methods(http.MethodPost)
	router.HandleFunc("/machine/map", noiseServer.NoisePollNetMapHandler)

	// __BEGIN_CYLONIX_ADD__
	router.HandleFunc("/machine/exit-node", noiseServer.NoiseExitNodeHandler)
	router.HandleFunc("/machine/update-health", noiseServer.NoiseUpdateHealthHandler)
	router.HandleFunc("/machine/cap", noiseServer.NoiseCapHandler)

	// Default handler for debugging unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("query", r.URL.RawQuery).
			Str("remote_addr", r.RemoteAddr).
			Interface("headers", r.Header).
			Msg("Unhandled request received on Noise connection")

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found"))
	})
	// __END_CYLONIX_ADD__

	server := http.Server{
		ReadTimeout: types.HTTPTimeout,
	}

	noiseServer.httpBaseConfig = &http.Server{
		Handler:           router,
		ReadHeaderTimeout: types.HTTPTimeout,
	}
	noiseServer.http2Server = &http2.Server{}

	server.Handler = h2c.NewHandler(router, noiseServer.http2Server)

	noiseServer.http2Server.ServeConn(
		noiseConn,
		&http2.ServeConnOpts{
			BaseConfig: noiseServer.httpBaseConfig,
		},
	)
}

func (ns *noiseServer) earlyNoise(protocolVersion int, writer io.Writer) (err error) {
	// __BEGIN_CYLONIX_MOD__
	defer func() {
		if err != nil {
			log.Debug().
				Caller().
				Err(err).
				Int("protocol_version", protocolVersion).
				Msg("failed in earlyNoise")
		}
	}()
	// __END_CYLONIX_MOD__
	log.Trace().
		Caller().
		Int("protocol_version", protocolVersion).
		Str("challenge", ns.challenge.Public().String()).
		Msg("earlyNoise called")

	if protocolVersion < earlyNoiseCapabilityVersion {
		log.Trace().
			Caller().
			Msgf("protocol version %d does not support early noise", protocolVersion)

		return nil
	}

	earlyJSON, err := json.Marshal(&tailcfg.EarlyNoise{
		NodeKeyChallenge: ns.challenge.Public(),
	})
	if err != nil {
		return err
	}

	// 5 bytes that won't be mistaken for an HTTP/2 frame:
	// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1 (Especially not
	// an HTTP/2 settings frame, which isn't of type 'T')
	var notH2Frame [5]byte
	copy(notH2Frame[:], earlyPayloadMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON)))
	// These writes are all buffered by caller, so fine to do them
	// separately:
	if _, err := writer.Write(notH2Frame[:]); err != nil {
		return err
	}
	if _, err := writer.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := writer.Write(earlyJSON); err != nil {
		return err
	}

	return nil
}

const (
	MinimumCapVersion tailcfg.CapabilityVersion = 61
)

// NoisePollNetMapHandler takes care of /machine/:id/map using the Noise protocol
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (ns *noiseServer) NoisePollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().
		Str("handler", "NoisePollNetMap").
		Msg("PollNetMapHandler called")

	log.Trace().
		Any("headers", req.Header).
		Caller().
		Msg("Headers")

	body, _ := io.ReadAll(req.Body)

	// __BEGIN_CYLONIX_ADD__
	namespace := ns.namespace
	if namespace == "" {
		namespace = req.Header.Get("namespace")
	}
	// __END_CYLONIX_ADD__

	mapRequest := tailcfg.MapRequest{}
	if err := json.Unmarshal(body, &mapRequest); err != nil {
		sub := len(body)
		if sub > 200 {
			sub = 200
		}
		log.Error().
			Caller().
			Err(err).
			Str("namespace", namespace). // __CYLONIX_ADD__
			Str("network_domain", ns.networkDomain). // __CYLONIX_ADD__
			Str("body", string(body[:sub])). // __CYLONIX_ADD__
			Int("body_length", len(body)). // __CYLONIX_ADD__
			Msg("Cannot parse MapRequest")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	// Reject unsupported versions
	if mapRequest.Version < MinimumCapVersion {
		log.Info().
			Caller().
			Int("min_version", int(MinimumCapVersion)).
			Int("client_version", int(mapRequest.Version)).
			Msg("unsupported client connected")
		http.Error(writer, "Internal error", http.StatusBadRequest)

		return
	}

	ns.nodeKey = mapRequest.NodeKey

	// __BEGIN_CYLONIX_MOD__
	hostname := ""
	if mapRequest.Hostinfo != nil {
		hostname = mapRequest.Hostinfo.Hostname
	}
	// __END_CYLONIX_MOD__

	node, err := ns.headscale.db.GetNodeByNodeKey(mapRequest.NodeKey) // __CYLONIX_MOD__
	if err != nil {
		log.Error().
			Str("handler", "NoisePollNetMap").
			Err(err). // __CYLONIX_ADD__
			Str("hostname", hostname). // __CYLONIX_ADD__
			Str("namespace", req.Header.Get("namespace")). // __CYLONIX_ADD__
			Msgf("Failed to fetch node from the database with node key: %s", mapRequest.NodeKey.String())

		// __BEGIN_CYLONIX_MOD__
		msg := "Internal error"
		code := http.StatusInternalServerError
		if ns.headscale.cfg.NodeHandler != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			if err := ns.headscale.cfg.NodeHandler.Recover(ns.conn.Peer(), mapRequest.NodeKey); err != nil {
				log.Error().Err(err).
					Str("namespace", req.Header.Get("namespace")).
					Str("machine-key", ns.conn.Peer().ShortString()).
					Str("node-key", mapRequest.NodeKey.ShortString()).
					Str("hostname", hostname).
					Msg("Failed to recover.")
				msg = "Failed to find node"
			} else {
				msg = "Machine needs approval"
			}
			code = http.StatusUnauthorized
		}
		http.Error(writer, msg, code)
		// __END_CYLONIX_MOD__
		return
	}

	ns.networkDomain = node.NetworkDomain // __CYLONIX_ADD__
	ns.namespace = node.Namespace         // __CYLONIX_ADD__

	sess := ns.headscale.newMapSession(req.Context(), mapRequest, writer, node)
	sess.tracef("a node sending a MapRequest with Noise protocol")
	if !sess.isStreaming() {
		sess.serve()
	} else {
		sess.serveLongPoll()
	}
}

// __BEGIN_CYLONIX_ADD__
// NoiseExitNodeHandler takes care of /machine/:id/exit-node using the Noise protocol
func (ns *noiseServer) NoiseExitNodeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Debug().
		Str("handler", "ExitNodeHandler").
		Msg("ExitNodeHandler called")

	log.Debug().
		Any("headers", req.Header).
		Caller().
		Msg("Headers")


	// Extract node key and exit node ID from query parameters
	nodeKeyStr := req.URL.Query().Get("node_key")
	exitNodeID := req.URL.Query().Get("exit_node_id")

	var requestedNodeKey key.NodePublic
	if nodeKeyStr != "" {
		if err := requestedNodeKey.UnmarshalText([]byte(nodeKeyStr)); err != nil {
			log.Warn().
				Caller().
				Str("node_key", nodeKeyStr).
				Err(err).
				Msg("Invalid node key in request parameters")
			http.Error(writer, "Invalid node key", http.StatusBadRequest)
			return
		}
	}
	log.Debug().
		Str("node_key", nodeKeyStr).
		Str("exit_node_id", exitNodeID).
		Msg("ExitNodeHandler parameters")

	node, err := ns.headscale.db.GetNodeByNodeKey(requestedNodeKey) // __CYLONIX_MOD__
	if err != nil {
		log.Error().Err(err).
			Str("handler", "ExitNodeHandler").
			Str("exit-node", exitNodeID).
			Msgf("Failed to fetch node from the database with node key: %s", requestedNodeKey.String())
		msg := "Internal error"
		code := http.StatusInternalServerError
		http.Error(writer, msg, code)
		return
	}
	if ns.headscale.cfg.NodeHandler != nil {
		if err := ns.headscale.cfg.NodeHandler.SetExitNode(node, exitNodeID); err != nil {
			log.Error().
				Str("handler", "ExitNodeHandler").
				Str("exit-node", exitNodeID).
				Err(err).
				Msg("Failed to set exit node")
			msg := "Failed to set exit node"
			code := http.StatusInternalServerError
			http.Error(writer, msg, code)
			return
		}
	}
}

var (
	healthErrLogMu    sync.Mutex
	healthErrLogCache = make(map[key.NodePublic]time.Time)
)

// NoiseUpdateHealthHandler takes care of /machine/:id/update-health using the Noise protocol
func (ns *noiseServer) NoiseUpdateHealthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().
		Str("handler", "UpdateHealthHandler").
		Msg("UpdateHealthHandler called")

	// Extract node key and health status from json body
	var update tailcfg.HealthChangeRequest
	if err := json.NewDecoder(req.Body).Decode(&update); err != nil {
		log.Warn().
			Caller().
			Err(err).
			Msg("Failed to decode request body")
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}
	if update.NodeKey.IsZero() {
		log.Warn().
			Caller().
			Msg("Missing node key in request body")
		http.Error(writer, "Missing node key", http.StatusBadRequest)
		return
	}
	log.Trace().
		Str("node", update.NodeKey.ShortString()).
		Str("subsys", update.Subsys).
		Str("error", update.Error).
		Msg("UpdateHealthHandler parameters")

	nodeLite, err := ns.headscale.db.GetNodeByNodeKeyLite(update.NodeKey) // __CYLONIX_MOD__
	if err != nil {
		// Throttle error logs: only log once per 5 minutes per node key.
		healthErrLogMu.Lock()
		last, exists := healthErrLogCache[update.NodeKey]
		now := time.Now()
		shouldLog := !exists || now.Sub(last) > 5*time.Minute
		if shouldLog {
			healthErrLogCache[update.NodeKey] = now
		}
		healthErrLogMu.Unlock()

		if shouldLog {
			log.Error().Err(err).
				Str("handler", "UpdateHealthHandler").
				Str("node", update.NodeKey.ShortString()).
				Msg("Failed to fetch node from the database")
		}
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}

	err = ns.headscale.db.UpdateNodeHealth(nodeLite, &update)
	if err != nil {
		log.Error().
			Str("handler", "UpdateHealthHandler").
			Str("node", update.NodeKey.ShortString()).
			Err(err).
			Msg("Failed to update node health")
		msg := "Internal error"
		code := http.StatusInternalServerError
		http.Error(writer, msg, code)
		return
	}
}

// NoiseCapHandler takes care of /machine/cap using the Noise protocol
func (ns *noiseServer) NoiseCapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	cap := req.URL.Query().Get("cap")
	op := req.URL.Query().Get("op")
	nodeKeyStr := req.URL.Query().Get("node_key")
	log.Debug().
		Str("handler", "CapHandler").
		Str("cap", cap).
		Str("op", op).
		Str("node_key", nodeKeyStr).
		Msg("CapHandler called")

	log.Debug().
		Any("headers", req.Header).
		Caller().
		Msg("Headers")

	if nodeKeyStr == "" || cap == "" || (op != "add" && op != "del") {
		log.Warn().
			Caller().
			Msg("Invalid node key, cap or op in request parameters")
		http.Error(writer, "Invalid request", http.StatusBadRequest)
		return
	}

	var requestedNodeKey key.NodePublic
	if err := requestedNodeKey.UnmarshalText([]byte(nodeKeyStr)); err != nil {
			log.Warn().
				Caller().
				Str("node_key", nodeKeyStr).
				Err(err).
				Msg("Invalid node key in request parameters")
			http.Error(writer, "Invalid node key", http.StatusBadRequest)
			return
		}
	log.Debug().
		Str("node", requestedNodeKey.ShortString()).
		Str("cap", cap).
		Str("op", op).
		Msg("CapHandler parameters")

	nodeLite, err := ns.headscale.db.GetNodeByNodeKeyLite(requestedNodeKey) // __CYLONIX_MOD__
	if err != nil {
		log.Error().Err(err).
			Str("handler", "CapHandler").
			Str("node", requestedNodeKey.ShortString()).
			Msg("Failed to fetch node from the database")
		msg := "Internal error"
		code := http.StatusInternalServerError
		http.Error(writer, msg, code)
		return
	}
	var addCapabilities []string
	var delCapabilities []string
	if op == "add" {
		addCapabilities = append(addCapabilities, cap)
	} else {
		delCapabilities = append(delCapabilities, cap)
	}
	err = ns.headscale.db.UpdateNode(
		nodeLite.ID,
		nodeLite.Namespace,
		&types.Node{},
		addCapabilities,
		delCapabilities,
	)
	if err != nil {
		log.Error().
			Str("handler", "CapHandler").
			Str("node", requestedNodeKey.ShortString()).
			Err(err).
			Msg("Failed to update node capabilities")
		msg := "Internal error"
		code := http.StatusInternalServerError
		http.Error(writer, msg, code)
		return
	}
	log.Info().
		Str("node", requestedNodeKey.ShortString()).
		Str("cap", cap).
		Str("op", op).
		Msg("Node capabilities updated successfully")
}
// __END_CYLONIX_ADD__