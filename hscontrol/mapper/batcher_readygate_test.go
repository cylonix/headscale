package mapper

// __BEGIN_CYLONIX_ADD__ Tests for the connection readiness gate that closes
// the empty-netmap race: updates broadcast between AddNode registering a
// connection and the initial full map being enqueued must be buffered behind
// the full map, never delivered ahead of it, and never treated as failures.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestConnectionEntryPreReadyBuffersAndFlushesInOrder(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 8)
	entry := &connectionEntry{id: "test", c: ch}

	patch1 := &tailcfg.MapResponse{Domain: "patch1"}
	patch2 := &tailcfg.MapResponse{Domain: "patch2"}

	// Updates delivered before the initial map are buffered and reported
	// as success, not written to the channel.
	require.NoError(t, entry.send(patch1))
	require.NoError(t, entry.send(patch2))
	require.Empty(t, ch)

	// AddNode enqueues the initial map directly, then opens the gate.
	full := &tailcfg.MapResponse{Domain: "full", DERPMap: &tailcfg.DERPMap{}}
	ch <- full
	entry.markReady()

	// Order: initial full map first, buffered updates behind it, FIFO.
	require.Equal(t, full, <-ch)
	require.Equal(t, patch1, <-ch)
	require.Equal(t, patch2, <-ch)

	// Post-ready sends go straight to the channel.
	patch3 := &tailcfg.MapResponse{Domain: "patch3"}
	require.NoError(t, entry.send(patch3))
	require.Equal(t, patch3, <-ch)
}

func TestConnectionEntryMarkReadyWithoutPending(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 2)
	entry := &connectionEntry{id: "test", c: ch}

	entry.markReady()

	patch := &tailcfg.MapResponse{Domain: "patch"}
	require.NoError(t, entry.send(patch))
	require.Equal(t, patch, <-ch)
}

func TestMultiChannelSendDoesNotRemoveGatedConnection(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := &connectionEntry{id: "gated", c: ch}
	mc.addConnection(entry)

	// A broadcast into a not-yet-ready connection is buffered, not treated
	// as a send failure: the connection must survive the broadcast.
	require.NoError(t, mc.send(&tailcfg.MapResponse{}))
	require.Equal(t, 1, mc.getActiveConnectionCount())
	require.Empty(t, ch)

	// After the gate opens, the buffered broadcast is delivered.
	entry.markReady()
	require.Len(t, ch, 1)
}

func TestConnectionEntryPreReadyOverflowErrors(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := &connectionEntry{id: "overflow", c: ch}

	for range maxPendingPreReady {
		require.NoError(t, entry.send(&tailcfg.MapResponse{}))
	}

	// Exceeding the buffer cap is a real error so the connection gets
	// dropped and the client reconnects cleanly.
	require.Error(t, entry.send(&tailcfg.MapResponse{}))
}

// __END_CYLONIX_ADD__
