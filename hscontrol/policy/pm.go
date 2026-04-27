package policy

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

type PolicyManager interface {
	// Filter returns the current filter rules for the entire tailnet and the associated matchers.
	Filter() ([]tailcfg.FilterRule, []matcher.Match)
	// FilterForNode returns filter rules for a specific node, handling autogroup:self
	FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error)
	// MatchersForNode returns matchers for peer relationship determination (unreduced)
	MatchersForNode(node types.NodeView) ([]matcher.Match, error)
	// BuildPeerMap constructs peer relationship maps for the given nodes
	BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeView
	// __BEGIN_CYLONIX_ADD__
	// BuildPeerMapForTailnet constructs peer relationship maps for a single
	// cylonix tailnet (network_domain). The returned map is keyed by IDs in
	// ownNodes only; sharedInNodes/sharedOutNodes participate in the
	// matcher domain but do not get their own entries here. See the v2
	// implementation for details.
	BuildPeerMapForTailnet(
		tailnet string,
		ownNodes views.Slice[types.NodeView],
		sharedInNodes views.Slice[types.NodeView],
		sharedOutNodes views.Slice[types.NodeView],
	) map[types.NodeID][]types.NodeView
	// __END_CYLONIX_ADD__
	SSHPolicy(types.NodeView) (*tailcfg.SSHPolicy, error)
	SetPolicy([]byte) (bool, error)
	// __BEGIN_CYLONIX_ADD__
	// SetTailnetPolicy installs a per-tailnet policy keyed by the given
	// tailnet identifier (network_domain). Returns true if the matchers
	// for that tailnet actually changed. When polB is empty, the entry
	// is cleared (equivalent to ClearTailnetPolicy).
	SetTailnetPolicy(tailnet string, polB []byte) (bool, error)
	// ClearTailnetPolicy removes any per-tailnet policy under the given
	// tailnet identifier so subsequent BuildPeerMapForTailnet calls fall
	// back to the global policy. Returns true if an entry was removed.
	ClearTailnetPolicy(tailnet string) bool
	// ValidateTailnetPolicy compiles polB the same way SetTailnetPolicy
	// would, but discards the result. Returns nil on success or the
	// compile error. Used by gRPC SetPolicy in multi-tenant mode to
	// reject malformed policies before they hit the database.
	ValidateTailnetPolicy(polB []byte) error
	// __END_CYLONIX_ADD__
	SetUsers(users []types.User) (bool, error)
	SetNodes(nodes views.Slice[types.NodeView]) (bool, error)
	// NodeCanHaveTag reports whether the given node can have the given tag.
	NodeCanHaveTag(types.NodeView, string) bool

	// TagExists reports whether the given tag is defined in the policy.
	TagExists(tag string) bool

	// NodeCanApproveRoute reports whether the given node can approve the given route.
	NodeCanApproveRoute(types.NodeView, netip.Prefix) bool

	Version() int
	DebugString() string
}

// NewPolicyManager returns a new policy manager.
func NewPolicyManager(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) (PolicyManager, error) {
	var polMan PolicyManager
	var err error
	polMan, err = policyv2.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return nil, err
	}

	return polMan, err
}

// PolicyManagersForTest returns all available PostureManagers to be used
// in tests to validate them in tests that try to determine that they
// behave the same.
func PolicyManagersForTest(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) ([]PolicyManager, error) {
	var polMans []PolicyManager

	for _, pmf := range PolicyManagerFuncsForTest(pol) {
		pm, err := pmf(users, nodes)
		if err != nil {
			return nil, err
		}
		polMans = append(polMans, pm)
	}

	return polMans, nil
}

func PolicyManagerFuncsForTest(pol []byte) []func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error) {
	var polmanFuncs []func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error)

	polmanFuncs = append(polmanFuncs, func(u []types.User, n views.Slice[types.NodeView]) (PolicyManager, error) {
		return policyv2.NewPolicyManager(pol, u, n)
	})

	return polmanFuncs
}
