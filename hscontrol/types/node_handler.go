package types

type NodeHandler interface {
	// PreAdd may alter the content in the Node before saving to the node DB.
	PreAdd(*Node) (*Node, error)

	// PostAdd does not change the node in the DB.
	PostAdd(*Node) error

	// Delete is invoked when a node is to be deleted
	Delete(*Node) error

	// Update is invoked when a node is updated.
	Update(*Node) (*Node, error)

	// Peers lists any peers additionly for the peers to be sent the requester.
	Peers(*Node) ([]*Node, error)
}