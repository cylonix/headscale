package types

import (
	"net/netip"

	"tailscale.com/types/key"
)

type IPAllocator interface {
	FreeWithMachinPublicKey(*netip.Addr, *key.MachinePublic) error
	NextWithMachinPublicKey(*key.MachinePublic) (*netip.Addr, *netip.Addr, error)
	NextV4() (*netip.Addr, error)
	NextV6() (*netip.Addr, error)
	PrefixV4() *netip.Prefix
	PrefixV6() *netip.Prefix
}