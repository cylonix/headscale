package state

import (
	"fmt"
	"maps"
	"strings"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

const (
	put             = 1
	del             = 2
	update          = 3
	rebuildPeerMaps = 4
	// __BEGIN_CYLONIX_ADD__
	// invalidateTailnet marks a single tailnet's peer cache as stale without
	// recomputing it. The next reader for that tailnet (via the orchestrator
	// in state.go) is responsible for triggering RebuildTailnet.
	invalidateTailnet = 5
	// rebuildTailnet pushes a freshly-computed peer map for a single
	// tailnet into the snapshot, also refreshing the matching entries in
	// the flattened peersByNode mirror.
	rebuildTailnet = 6
	// __END_CYLONIX_ADD__
)

const prometheusNamespace = "headscale"

var (
	nodeStoreOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_operations_total",
		Help:      "Total number of NodeStore operations",
	}, []string{"operation"})
	nodeStoreOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_operation_duration_seconds",
		Help:      "Duration of NodeStore operations",
		Buckets:   prometheus.DefBuckets,
	}, []string{"operation"})
	nodeStoreBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_batch_size",
		Help:      "Size of NodeStore write batches",
		Buckets:   []float64{1, 2, 5, 10, 20, 50, 100},
	})
	nodeStoreBatchDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_batch_duration_seconds",
		Help:      "Duration of NodeStore batch processing",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreSnapshotBuildDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_snapshot_build_duration_seconds",
		Help:      "Duration of NodeStore snapshot building from nodes",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreNodesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_nodes_total",
		Help:      "Total number of nodes in the NodeStore",
	})
	nodeStorePeersCalculationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_peers_calculation_duration_seconds",
		Help:      "Duration of peers calculation in NodeStore",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_queue_depth",
		Help:      "Current depth of NodeStore write queue",
	})
)

// NodeStore is a thread-safe store for nodes.
// It is a copy-on-write structure, replacing the "snapshot"
// when a change to the structure occurs. It is optimised for reads,
// and while batches are not fast, they are grouped together
// to do less of the expensive peer calculation if there are many
// changes rapidly.
//
// Writes will block until committed, while reads are never
// blocked. This means that the caller of a write operation
// is responsible for ensuring an update depending on a write
// is not issued before the write is complete.
type NodeStore struct {
	data atomic.Pointer[Snapshot]

	peersFunc  PeersFunc
	writeQueue chan work

	batchSize    int
	batchTimeout time.Duration
}

func NewNodeStore(allNodes types.Nodes, peersFunc PeersFunc, batchSize int, batchTimeout time.Duration) *NodeStore {
	nodes := make(map[types.NodeID]types.Node, len(allNodes))
	for _, n := range allNodes {
		nodes[n.ID] = *n
	}
	snap := snapshotFromNodes(nodes, peersFunc)

	store := &NodeStore{
		peersFunc:    peersFunc,
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
	}
	store.data.Store(&snap)

	// Initialize node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	return store
}

// __BEGIN_CYLONIX_ADD__
// tailnetPeerCache holds the lazily-computed peer map for a single
// cylonix tailnet (network_domain). `valid == false` means the entry has
// been invalidated and must be rebuilt before reads can use `peers`.
// `peers` is keyed by the tailnet's own node IDs only — see
// policy.PolicyManager.BuildPeerMapForTailnet.
type tailnetPeerCache struct {
	peers map[types.NodeID][]types.NodeView
	valid bool
}

// __END_CYLONIX_ADD__

// Snapshot is the representation of the current state of the NodeStore.
// It contains all nodes and their relationships.
// It is a copy-on-write structure, meaning that when a write occurs,
// a new Snapshot is created with the updated state,
// and replaces the old one atomically.
type Snapshot struct {
	// nodesByID is the main source of truth for nodes.
	nodesByID map[types.NodeID]types.Node

	// calculated from nodesByID
	nodesByNodeKey    map[key.NodePublic]types.NodeView
	nodesByMachineKey map[key.MachinePublic]map[types.UserID]types.NodeView
	peersByNode       map[types.NodeID][]types.NodeView
	nodesByUser       map[types.UserID][]types.NodeView
	allNodes          []types.NodeView
	// __BEGIN_CYLONIX_ADD__
	// peersByTailnet is the per-tailnet peer cache. Each entry is computed
	// lazily on first read after invalidation by the orchestrator in
	// state.go. Entries co-exist independently — invalidating one tailnet
	// does not touch the others. peersByNode remains a flattened mirror so
	// existing read paths that aren't tailnet-aware keep working.
	peersByTailnet map[string]tailnetPeerCache
	// __END_CYLONIX_ADD__
}

// PeersFunc is a function that takes a list of nodes and returns a map
// with the relationships between nodes and their peers.
// This will typically be used to calculate which nodes can see each other
// based on the current policy.
type PeersFunc func(nodes []types.NodeView) map[types.NodeID][]types.NodeView

// work represents a single operation to be performed on the NodeStore.
type work struct {
	op         int
	nodeID     types.NodeID
	node       types.Node
	updateFn   UpdateNodeFunc
	result     chan struct{}
	nodeResult chan types.NodeView // Channel to return the resulting node after batch application
	// For rebuildPeerMaps operation
	rebuildResult chan struct{}
	// __BEGIN_CYLONIX_ADD__
	// Per-tailnet ops (invalidateTailnet / rebuildTailnet)
	tailnet         string
	tailnetPeers    map[types.NodeID][]types.NodeView
	tailnetOwnIDs   []types.NodeID
	// __END_CYLONIX_ADD__
}

// PutNode adds or updates a node in the store.
// If the node already exists, it will be replaced.
// If the node does not exist, it will be added.
// This is a blocking operation that waits for the write to complete.
// Returns the resulting node after all modifications in the batch have been applied.
func (s *NodeStore) PutNode(n types.Node) types.NodeView {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("put"))
	defer timer.ObserveDuration()

	work := work{
		op:         put,
		nodeID:     n.ID,
		node:       n,
		result:     make(chan struct{}),
		nodeResult: make(chan types.NodeView, 1),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	resultNode := <-work.nodeResult
	nodeStoreOperations.WithLabelValues("put").Inc()

	return resultNode
}

// UpdateNodeFunc is a function type that takes a pointer to a Node and modifies it.
type UpdateNodeFunc func(n *types.Node)

// UpdateNode applies a function to modify a specific node in the store.
// This is a blocking operation that waits for the write to complete.
// This is analogous to a database "transaction", or, the caller should
// rather collect all data they want to change, and then call this function.
// Fewer calls are better.
// Returns the resulting node after all modifications in the batch have been applied.
//
// TODO(kradalby): Technically we could have a version of this that modifies the node
// in the current snapshot if _we know_ that the change will not affect the peer relationships.
// This is because the main nodesByID map contains the struct, and every other map is using a
// pointer to the underlying struct. The gotcha with this is that we will need to introduce
// a lock around the nodesByID map to ensure that no other writes are happening
// while we are modifying the node. Which mean we would need to implement read-write locks
// on all read operations.
func (s *NodeStore) UpdateNode(nodeID types.NodeID, updateFn func(n *types.Node)) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("update"))
	defer timer.ObserveDuration()

	work := work{
		op:         update,
		nodeID:     nodeID,
		updateFn:   updateFn,
		result:     make(chan struct{}),
		nodeResult: make(chan types.NodeView, 1),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	resultNode := <-work.nodeResult
	nodeStoreOperations.WithLabelValues("update").Inc()

	// Return the node and whether it exists (is valid)
	return resultNode, resultNode.Valid()
}

// DeleteNode removes a node from the store by its ID.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) DeleteNode(id types.NodeID) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("delete"))
	defer timer.ObserveDuration()

	work := work{
		op:     del,
		nodeID: id,
		result: make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("delete").Inc()
}

// Start initializes the NodeStore and starts processing the write queue.
func (s *NodeStore) Start() {
	s.writeQueue = make(chan work)
	go s.processWrite()
}

// Stop stops the NodeStore.
func (s *NodeStore) Stop() {
	close(s.writeQueue)
}

// processWrite processes the write queue in batches.
func (s *NodeStore) processWrite() {
	c := time.NewTicker(s.batchTimeout)
	defer c.Stop()

	batch := make([]work, 0, s.batchSize)

	for {
		select {
		case w, ok := <-s.writeQueue:
			if !ok {
				// Channel closed, apply any remaining batch and exit
				if len(batch) != 0 {
					s.applyBatch(batch)
				}
				return
			}
			batch = append(batch, w)
			if len(batch) >= s.batchSize {
				s.applyBatch(batch)
				batch = batch[:0]

				c.Reset(s.batchTimeout)
			}
		case <-c.C:
			if len(batch) != 0 {
				s.applyBatch(batch)
				batch = batch[:0]
			}

			c.Reset(s.batchTimeout)
		}
	}
}

// applyBatch applies a batch of work to the node store.
// This means that it takes a copy of the current nodes,
// then applies the batch of operations to that copy,
// runs any precomputation needed (like calculating peers),
// and finally replaces the snapshot in the store with the new one.
// The replacement of the snapshot is atomic, ensuring that reads
// are never blocked by writes.
// Each write item is blocked until the batch is applied to ensure
// the caller knows the operation is complete and do not send any
// updates that are dependent on a read that is yet to be written.
func (s *NodeStore) applyBatch(batch []work) {
	timer := prometheus.NewTimer(nodeStoreBatchDuration)
	defer timer.ObserveDuration()

	nodeStoreBatchSize.Observe(float64(len(batch)))

	prevSnap := s.data.Load()
	nodes := make(map[types.NodeID]types.Node)
	maps.Copy(nodes, prevSnap.nodesByID)

	// Track which work items need node results
	nodeResultRequests := make(map[types.NodeID][]*work)

	// Track rebuildPeerMaps operations
	var rebuildOps []*work

	// __BEGIN_CYLONIX_ADD__
	// Per-tailnet cache mutations collected over the batch. They are
	// applied to the new snapshot below.
	invalidatedTailnets := make(map[string]struct{})
	rebuiltTailnets := make(map[string]map[types.NodeID][]types.NodeView)
	rebuiltOwnIDs := make(map[string][]types.NodeID)
	// Track whether any node-mutation op (put/update/del) ran in this
	// batch so we know whether to do a global peersFunc rebuild for the
	// non-tailnet path.
	hadNodeMutation := false
	// __END_CYLONIX_ADD__

	for i := range batch {
		w := &batch[i]
		switch w.op {
		case put:
			nodes[w.nodeID] = w.node
			hadNodeMutation = true // __CYLONIX_ADD__
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case update:
			// Update the specific node identified by nodeID
			if n, exists := nodes[w.nodeID]; exists {
				w.updateFn(&n)
				nodes[w.nodeID] = n
			}
			hadNodeMutation = true // __CYLONIX_ADD__
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case del:
			delete(nodes, w.nodeID)
			hadNodeMutation = true // __CYLONIX_ADD__
			// For delete operations, send an invalid NodeView if requested
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case rebuildPeerMaps:
			// rebuildPeerMaps doesn't modify nodes, it just forces the snapshot rebuild
			// below to recalculate peer relationships using the current peersFunc
			rebuildOps = append(rebuildOps, w)
		// __BEGIN_CYLONIX_ADD__
		case invalidateTailnet:
			if w.tailnet != "" {
				invalidatedTailnets[w.tailnet] = struct{}{}
			}
		case rebuildTailnet:
			if w.tailnet != "" {
				rebuiltTailnets[w.tailnet] = w.tailnetPeers
				rebuiltOwnIDs[w.tailnet] = w.tailnetOwnIDs
				// A rebuild supersedes any prior invalidation for the same tailnet.
				delete(invalidatedTailnets, w.tailnet)
			}
		// __END_CYLONIX_ADD__
		}
	}

	// __BEGIN_CYLONIX_MOD__
	// Decide how to compute the new snapshot. The legacy peersFunc path
	// (used when there is no NodeHandler / when callers haven't switched
	// to the per-tailnet API) still rebuilds the full peersByNode map on
	// any node mutation — that's what the upstream-style deployments and
	// existing tests rely on. When the only ops in the batch are pure
	// tailnet cache mutations (invalidate/rebuild), we don't need to
	// touch peersFunc; we just inherit the previous snapshot's
	// peersByNode and overlay the per-tailnet cache.
	var newSnap Snapshot
	if hadNodeMutation || len(rebuildOps) > 0 {
		newSnap = snapshotFromNodes(nodes, s.peersFunc)
	} else {
		newSnap = snapshotFromNodesNoPeers(nodes, prevSnap)
	}

	// Carry forward the per-tailnet cache from the previous snapshot.
	if newSnap.peersByTailnet == nil {
		newSnap.peersByTailnet = make(map[string]tailnetPeerCache, len(prevSnap.peersByTailnet))
	}
	for k, v := range prevSnap.peersByTailnet {
		newSnap.peersByTailnet[k] = v
	}

	// On any node mutation, the affected tailnets' caches must be marked
	// stale. The orchestrator in state.go is responsible for figuring
	// out which tailnets — here we only know the changed nodes, so we
	// look at their network_domain in both the old and new snapshots
	// and invalidate those.
	if hadNodeMutation {
		affected := make(map[string]struct{})
		// Look at touched node IDs in the old snapshot.
		for i := range batch {
			w := &batch[i]
			if w.op != put && w.op != update && w.op != del {
				continue
			}
			if oldN, ok := prevSnap.nodesByID[w.nodeID]; ok {
				if oldN.NetworkDomain != "" {
					affected[oldN.NetworkDomain] = struct{}{}
				}
			}
			if newN, ok := nodes[w.nodeID]; ok {
				if newN.NetworkDomain != "" {
					affected[newN.NetworkDomain] = struct{}{}
				}
			}
		}
		for t := range affected {
			c := newSnap.peersByTailnet[t]
			c.valid = false
			newSnap.peersByTailnet[t] = c
		}
	}

	// Apply explicit invalidations.
	for t := range invalidatedTailnets {
		c := newSnap.peersByTailnet[t]
		c.valid = false
		newSnap.peersByTailnet[t] = c
	}

	// Apply explicit rebuilds (which also refresh the matching slice of
	// the flattened peersByNode mirror so non-tailnet readers see the
	// new state).
	for t, peers := range rebuiltTailnets {
		// Defensive copy: snapshotFromNodes returned a fresh map; if we
		// inherited the previous snapshot's map (no node mutation case),
		// peersByNode might still be the old one — clone before mutating.
		if newSnap.peersByNode == nil {
			newSnap.peersByNode = make(map[types.NodeID][]types.NodeView)
		} else if !hadNodeMutation && len(rebuildOps) == 0 {
			// We may be sharing the previous map reference; clone.
			cloned := make(map[types.NodeID][]types.NodeView, len(newSnap.peersByNode))
			for k, v := range newSnap.peersByNode {
				cloned[k] = v
			}
			newSnap.peersByNode = cloned
		}
		for _, id := range rebuiltOwnIDs[t] {
			if p, ok := peers[id]; ok {
				newSnap.peersByNode[id] = p
			} else {
				delete(newSnap.peersByNode, id)
			}
		}
		newSnap.peersByTailnet[t] = tailnetPeerCache{peers: peers, valid: true}
	}
	// __END_CYLONIX_MOD__

	s.data.Store(&newSnap)

	// Update node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	// Send the resulting nodes to all work items that requested them
	for nodeID, workItems := range nodeResultRequests {
		if node, exists := nodes[nodeID]; exists {
			nodeView := node.View()
			for _, w := range workItems {
				w.nodeResult <- nodeView
				close(w.nodeResult)
			}
		} else {
			// Node was deleted or doesn't exist
			for _, w := range workItems {
				w.nodeResult <- types.NodeView{} // Send invalid view
				close(w.nodeResult)
			}
		}
	}

	// Signal completion for rebuildPeerMaps operations
	for _, w := range rebuildOps {
		close(w.rebuildResult)
	}

	// Signal completion for all other work items
	for _, w := range batch {
		if w.op != rebuildPeerMaps {
			close(w.result)
		}
	}
}

// snapshotFromNodes creates a new Snapshot from the provided nodes.
// It builds a lot of "indexes" to make lookups fast for datasets we
// that is used frequently, like nodesByNodeKey, peersByNode, and nodesByUser.
// This is not a fast operation, it is the "slow" part of our copy-on-write
// structure, but it allows us to have fast reads and efficient lookups.
func snapshotFromNodes(nodes map[types.NodeID]types.Node, peersFunc PeersFunc) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	newSnap := Snapshot{
		nodesByID:         nodes,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),

		// peersByNode is most likely the most expensive operation,
		// it will use the list of all nodes, combined with the
		// current policy to precalculate which nodes are peers and
		// can see each other.
		peersByNode: func() map[types.NodeID][]types.NodeView {
			peersTimer := prometheus.NewTimer(nodeStorePeersCalculationDuration)
			defer peersTimer.ObserveDuration()
			return peersFunc(allNodes)
		}(),
		nodesByUser: make(map[types.UserID][]types.NodeView),
		// __BEGIN_CYLONIX_ADD__
		peersByTailnet: make(map[string]tailnetPeerCache),
		// __END_CYLONIX_ADD__
	}

	// Build nodesByUser, nodesByNodeKey, and nodesByMachineKey maps
	for _, n := range nodes {
		nodeView := n.View()
		userID := n.TypedUserID()

		newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		// Build machine key index
		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}
		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

// __BEGIN_CYLONIX_ADD__
// snapshotFromNodesNoPeers builds a new Snapshot WITHOUT recomputing the
// global peersByNode map via peersFunc. Used when a batch contains only
// per-tailnet cache mutations (invalidate / rebuild) — those don't change
// the underlying node set, so we re-derive the cheap indexes and inherit
// the previous peersByNode reference. The caller is responsible for
// applying any rebuilt-tailnet overlays on top of peersByNode (with a
// proper clone first; see applyBatch).
func snapshotFromNodesNoPeers(nodes map[types.NodeID]types.Node, prev *Snapshot) Snapshot {
	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	newSnap := Snapshot{
		nodesByID:         nodes,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView, len(nodes)),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		peersByNode:       prev.peersByNode,
		nodesByUser:       make(map[types.UserID][]types.NodeView),
		peersByTailnet:    make(map[string]tailnetPeerCache, len(prev.peersByTailnet)),
	}

	for _, n := range nodes {
		nodeView := n.View()
		userID := n.TypedUserID()

		newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}
		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

// __END_CYLONIX_ADD__

// GetNode retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNode(id types.NodeID) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get").Inc()

	n, exists := s.data.Load().nodesByID[id]
	if !exists {
		return types.NodeView{}, false
	}

	return n.View(), true
}

// GetNodeByNodeKey retrieves a node by its NodeKey.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_key"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_key").Inc()

	nodeView, exists := s.data.Load().nodesByNodeKey[nodeKey]

	return nodeView, exists
}

// GetNodeByMachineKey returns a node by its machine key and user ID. The bool indicates if the node exists.
func (s *NodeStore) GetNodeByMachineKey(machineKey key.MachinePublic, userID types.UserID) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_machine_key"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_machine_key").Inc()

	snapshot := s.data.Load()
	if userMap, exists := snapshot.nodesByMachineKey[machineKey]; exists {
		if node, exists := userMap[userID]; exists {
			return node, true
		}
	}

	return types.NodeView{}, false
}

// GetNodeByMachineKeyAnyUser returns the first node with the given machine key,
// regardless of which user it belongs to. This is useful for scenarios like
// transferring a node to a different user when re-authenticating with a
// different user's auth key.
// If multiple nodes exist with the same machine key (different users), the
// first one found is returned (order is not guaranteed).
func (s *NodeStore) GetNodeByMachineKeyAnyUser(machineKey key.MachinePublic) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_machine_key_any_user"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_machine_key_any_user").Inc()

	snapshot := s.data.Load()
	if userMap, exists := snapshot.nodesByMachineKey[machineKey]; exists {
		// Return the first node found (order not guaranteed due to map iteration)
		for _, node := range userMap {
			return node, true
		}
	}

	return types.NodeView{}, false
}

// DebugString returns debug information about the NodeStore.
func (s *NodeStore) DebugString() string {
	snapshot := s.data.Load()

	var sb strings.Builder

	sb.WriteString("=== NodeStore Debug Information ===\n\n")

	// Basic counts
	sb.WriteString(fmt.Sprintf("Total Nodes: %d\n", len(snapshot.nodesByID)))
	sb.WriteString(fmt.Sprintf("Users with Nodes: %d\n", len(snapshot.nodesByUser)))
	sb.WriteString("\n")

	// User distribution (shows internal UserID tracking, not display owner)
	sb.WriteString("Nodes by Internal User ID:\n")
	for userID, nodes := range snapshot.nodesByUser {
		if len(nodes) > 0 {
			userName := "unknown"
			taggedCount := 0
			if len(nodes) > 0 && nodes[0].Valid() {
				userName = nodes[0].User().Name()
				// Count tagged nodes (which have UserID set but are owned by "tagged-devices")
				for _, n := range nodes {
					if n.IsTagged() {
						taggedCount++
					}
				}
			}

			if taggedCount > 0 {
				sb.WriteString(fmt.Sprintf("  - User %d (%s): %d nodes (%d tagged)\n", userID, userName, len(nodes), taggedCount))
			} else {
				sb.WriteString(fmt.Sprintf("  - User %d (%s): %d nodes\n", userID, userName, len(nodes)))
			}
		}
	}
	sb.WriteString("\n")

	// Peer relationships summary
	sb.WriteString("Peer Relationships:\n")
	totalPeers := 0
	for nodeID, peers := range snapshot.peersByNode {
		peerCount := len(peers)
		totalPeers += peerCount
		if node, exists := snapshot.nodesByID[nodeID]; exists {
			sb.WriteString(fmt.Sprintf("  - Node %d (%s): %d peers\n",
				nodeID, node.Hostname, peerCount))
		}
	}
	if len(snapshot.peersByNode) > 0 {
		avgPeers := float64(totalPeers) / float64(len(snapshot.peersByNode))
		sb.WriteString(fmt.Sprintf("  - Average peers per node: %.1f\n", avgPeers))
	}
	sb.WriteString("\n")

	// Node key index
	sb.WriteString(fmt.Sprintf("NodeKey Index: %d entries\n", len(snapshot.nodesByNodeKey)))
	sb.WriteString("\n")

	return sb.String()
}

// ListNodes returns a slice of all nodes in the store.
func (s *NodeStore) ListNodes() views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list").Inc()

	return views.SliceOf(s.data.Load().allNodes)
}

// ListPeers returns a slice of all peers for a given node ID.
func (s *NodeStore) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_peers"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_peers").Inc()

	return views.SliceOf(s.data.Load().peersByNode[id])
}

// RebuildPeerMaps rebuilds the peer relationship map using the current peersFunc.
// This must be called after policy changes because peersFunc uses PolicyManager's
// filters to determine which nodes can see each other. Without rebuilding, the
// peer map would use stale filter data until the next node add/delete.
//
// __BEGIN_CYLONIX_MOD__
// Deprecated for the multi-tenant path: prefer InvalidatePeersForTailnet
// + RebuildTailnet via the State orchestrator. RebuildPeerMaps still works
// for the single-tenant / upstream-style deployments where peersFunc
// against the global node set is the correct semantics, and is also used
// by the existing NodeStore unit tests.
// __END_CYLONIX_MOD__
func (s *NodeStore) RebuildPeerMaps() {
	result := make(chan struct{})

	w := work{
		op:            rebuildPeerMaps,
		rebuildResult: result,
	}

	s.writeQueue <- w
	<-result
}

// __BEGIN_CYLONIX_ADD__
// InvalidatePeersForTailnet marks the given tailnet's peer cache as stale
// in the next snapshot. It does NOT recompute — the next call to
// IsTailnetCacheValid for this tailnet returns false until the State
// orchestrator pushes a fresh map via RebuildTailnet.
//
// Concurrency: routed through the writeQueue (op = invalidateTailnet) so
// the change is applied via copy-on-write together with any in-flight
// node mutations.
func (s *NodeStore) InvalidatePeersForTailnet(tailnet string) {
	if tailnet == "" {
		return
	}

	w := work{
		op:      invalidateTailnet,
		tailnet: tailnet,
		result:  make(chan struct{}),
	}
	s.writeQueue <- w
	<-w.result
}

// IsTailnetCacheValid reports whether the per-tailnet peer cache for
// `tailnet` is currently valid. A missing entry counts as invalid (it
// must be built before reads can use it).
func (s *NodeStore) IsTailnetCacheValid(tailnet string) bool {
	if tailnet == "" {
		return false
	}
	c, ok := s.data.Load().peersByTailnet[tailnet]
	return ok && c.valid
}

// PeersForTailnet returns the peer slice for `nodeID` within `tailnet`'s
// per-tailnet cache. The bool reports whether the cache is currently
// valid; if false, callers should trigger a rebuild before retrying.
//
// This is the per-tailnet read path that pairs with RebuildTailnet — it
// bypasses the flattened peersByNode mirror so callers that have a
// tailnet identifier can avoid stale-mirror reads.
func (s *NodeStore) PeersForTailnet(tailnet string, nodeID types.NodeID) (views.Slice[types.NodeView], bool) {
	if tailnet == "" {
		return views.Slice[types.NodeView]{}, false
	}
	c, ok := s.data.Load().peersByTailnet[tailnet]
	if !ok || !c.valid {
		return views.Slice[types.NodeView]{}, false
	}
	return views.SliceOf(c.peers[nodeID]), true
}

// RebuildTailnet pushes a freshly-computed peer map for `tailnet` into
// the snapshot. `peerMap` must be keyed by IDs in `ownNodes` only (the
// shape returned by policy.PolicyManager.BuildPeerMapForTailnet). The
// peers slices may include sharedIn/sharedOut neighbours.
//
// In addition to populating peersByTailnet[tailnet], this refreshes the
// per-own-node entries in the flattened peersByNode mirror so existing
// tailnet-unaware readers see the new state. Other tailnets' entries in
// peersByNode are left untouched.
//
// Concurrency: routed through the writeQueue (op = rebuildTailnet).
func (s *NodeStore) RebuildTailnet(
	tailnet string,
	ownNodes views.Slice[types.NodeView],
	_ views.Slice[types.NodeView], // sharedInNodes — informational
	_ views.Slice[types.NodeView], // sharedOutNodes — informational
	peerMap map[types.NodeID][]types.NodeView,
) {
	if tailnet == "" {
		return
	}

	ownIDs := make([]types.NodeID, 0, ownNodes.Len())
	for _, n := range ownNodes.All() {
		if n.Valid() {
			ownIDs = append(ownIDs, n.ID())
		}
	}

	w := work{
		op:            rebuildTailnet,
		tailnet:       tailnet,
		tailnetPeers:  peerMap,
		tailnetOwnIDs: ownIDs,
		result:        make(chan struct{}),
	}
	s.writeQueue <- w
	<-w.result
}

// __END_CYLONIX_ADD__

// ListNodesByUser returns a slice of all nodes for a given user ID.
func (s *NodeStore) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_by_user"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_by_user").Inc()

	return views.SliceOf(s.data.Load().nodesByUser[uid])
}
