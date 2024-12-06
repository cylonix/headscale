package types

import (
	"net/netip"

	"tailscale.com/types/key"
)

type IPAllocator interface {
	FreeFor(*netip.Addr, *User, *key.MachinePublic) error
	NextFor(*User, *key.MachinePublic, *netip.Addr, *netip.Addr) (*netip.Addr, *netip.Addr, error)
	NextV4(*User) (*netip.Addr, error)
	NextV6(*User) (*netip.Addr, error)
	PrefixV4(*User) *netip.Prefix
	PrefixV6(*User) *netip.Prefix
}