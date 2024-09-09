package types

type NodeHandler interface {
	Add(*Node) (*Node, error)
	Delete(*Node) error
	Update(*Node) (*Node, error)
}