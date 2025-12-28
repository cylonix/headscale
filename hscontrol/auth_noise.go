package hscontrol

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// NoiseRegistrationHandler handles the actual registration process of a node.
func (ns *noiseServer) NoiseRegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise registration handler for client %s", req.RemoteAddr)
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}

	log.Trace().
		Any("headers", req.Header).
		Caller().
		Msg("Headers")

	// __BEGIN_CYLONIX_MOD__
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Debug().
			Caller().
			Err(err).
			Msg("Cannot read request body")
		http.Error(writer, "cannot read request body", http.StatusBadRequest)

		return
	}
	// __END_CYLONIX_MOD__
	registerRequest := tailcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		sub := len(body)
		if sub > 200 {
			sub = 200
		}
		log.Debug().
			Caller().
			Err(err).
			Str("body", string(body[:sub])).
			Int("body_length", len(body)).
			Msg("Cannot parse RegisterRequest")
		http.Error(writer, "cannot parse request", http.StatusBadRequest)

		return
	}

	// Reject unsupported versions
	if registerRequest.Version < MinimumCapVersion {
		log.Info().
			Caller().
			Int("min_version", int(MinimumCapVersion)).
			Int("client_version", int(registerRequest.Version)).
			Msg("unsupported client connected")
		http.Error(writer, "unsupported client version", http.StatusBadRequest)

		return
	}

	ns.nodeKey = registerRequest.NodeKey

	ns.headscale.handleRegister(writer, req, registerRequest, ns.conn.Peer())
}
