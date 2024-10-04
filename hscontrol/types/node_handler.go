package types

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type NodeHandler interface {
	// PreAdd may alter the content in the Node before saving to the node DB.
	PreAdd(*Node) (*Node, error)

	// PostAdd does not change the node in the DB.
	PostAdd(*Node) error

	// Delete is invoked when a node is to be deleted
	Delete(*Node) error

	// Update is invoked when a node is updated.
	Update(*Node) (*Node, error)

	// Recover is to recover a node that's already in polling but no matching
	// node found. A handler may simply add it to the approval queue again
	// or change it to pending if it is in approved state so that admin can
	// decide if to recover the node by re-approving it.
	Recover(key.MachinePublic, key.NodePublic) error

	// Peers lists any peers additionly for the peers to be sent the requester.
	Peers(*Node) (Nodes, []NodeID, error)

	// Profiles gets the user profiles base on the node slice.
	Profiles([]*Node)([]tailcfg.UserProfile, error)

	// Tailscale user info.
	User(*User) *tailcfg.User
	UserLogin(*User) *tailcfg.Login
	UserProfile(*User) *tailcfg.UserProfile
}
