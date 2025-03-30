package types

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type NodeHandler interface {
	// AuthURL is used to get the auth URL for a node.
	AuthURL(key.NodePublic) (string, error)

	// PreAdd may alter the content in the Node before saving to the node DB.
	PreAdd(*Node) (*Node, error)

	// PostAdd does not change the node in the DB.
	PostAdd(*Node) error

	// Delete is invoked when a node is to be deleted
	Delete(*Node) error

	// Update is invoked when a node is updated.
	Update(*Node) (*Node, error)

	// Refresh token refreshes the token that authorized the node.
	RefreshToken(*Node) error

	// RotateNodeKey is invoked when a node refresh its node key.
	// This is more specific than Update as it needs to trigger more processing
	// that any update that does not rotate the node key.
	RotateNodeKey(*Node, key.NodePublic) error

	// Recover is to recover a node that's already in polling but no matching
	// node found. A handler may simply add it to the approval queue again
	// or change it to pending if it is in approved state so that admin can
	// decide if to recover the node by re-approving it.
	Recover(key.MachinePublic, key.NodePublic) error

	// Peers lists any peers additional to the requester's own nodes.
	// Implementations can return part of the peers in nodes with 'peerNodes'
	// and/or just peer node IDs with 'peerNodeIDs', and optionally indicate
	// the online ones through the 'onlinePeers' return value.
	Peers(*Node) (peerNodes Nodes, peerNodeIDs []NodeID, onlinePeers []NodeID, err error)

	// Profiles gets the user profiles base on the node slice.
	Profiles([]*Node)([]tailcfg.UserProfile, error)

	// Tailscale user info.
	User(*User) *tailcfg.User
	UserLogin(*User) *tailcfg.Login
	UserProfile(*User) *tailcfg.UserProfile
}
