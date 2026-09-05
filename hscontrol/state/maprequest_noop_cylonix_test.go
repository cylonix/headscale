package state

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// A MapRequest whose only delta is the LastSeen stamp that
// PeerChangeFromMapRequest always sets must not produce a change that fans
// out to peers.
func TestBuildMapRequestChangeResponseNoOp(t *testing.T) {
	c, err := buildMapRequestChangeResponse(1, types.NodeView{}, false, false, false, false)
	require.NoError(t, err)
	require.True(t, c.IsEmpty(), "LastSeen-only MapRequest must yield an empty change")

	c, err = buildMapRequestChangeResponse(1, types.NodeView{}, false, false, false, true)
	require.NoError(t, err)
	require.False(t, c.IsEmpty(), "key/disco/expiry/online change must still reach peers")
	require.Equal(t, []types.NodeID{1}, c.PeersChanged)

	c, err = buildMapRequestChangeResponse(1, types.NodeView{}, true, false, false, false)
	require.NoError(t, err)
	require.Equal(t, []types.NodeID{1}, c.PeersChanged, "hostinfo change still sends the node")
}

func TestPeerChangePersistWorthyIgnoresLastSeen(t *testing.T) {
	now := time.Now()

	require.False(t, peerChangePersistWorthy(tailcfg.PeerChange{}))
	require.False(t, peerChangeEmpty(tailcfg.PeerChange{LastSeen: &now}),
		"documenting upstream behaviour: LastSeen alone defeats peerChangeEmpty")
	require.False(t, peerChangePersistWorthy(tailcfg.PeerChange{LastSeen: &now}))
	require.True(t, peerChangePersistWorthy(tailcfg.PeerChange{Online: new(true)}))
}
