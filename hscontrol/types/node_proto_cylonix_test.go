// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"net/netip"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/types/key"
)

func TestParseProtoNodeForCreateHonorsIdentityAndPresence(t *testing.T) {
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	wgOnly := true
	capVer := uint32(25)

	p := &v1.Node{
		MachineKey:     mk.String(),
		NodeKey:        nk.String(),
		DiscoKey:       key.DiscoPublic{}.String(),
		IpAddresses:    []string{"100.90.150.122", "fd7a:115c:a1e0::9"},
		Name:           "wg-ca-17-v2",
		GivenName:      "wg-ca-17-v2",
		Namespace:      "acme",
		NetworkDomain:  "acme.net",
		RegisterMethod: v1.RegisterMethod_REGISTER_METHOD_CLI,
		Expiry:         timestamppb.New(expiry),
		Online:         true,
		Tags:           []string{"tag:gateway"},
		WireguardOnly:  &wgOnly,
		CapVersion:     &capVer,
		Endpoints:      []string{"134.199.212.130:54458"},
		Routes: []*v1.RouteSpec{
			{Prefix: "10.9.0.0/16", Enabled: true, Advertised: true},
			{Prefix: "10.10.0.0/16", Enabled: false, Advertised: true},
		},
		Capabilities: []string{"relay"},
	}

	n, err := ParseProtoNodeForCreate(p)
	require.NoError(t, err)

	require.Equal(t, mk, n.MachineKey)
	require.Equal(t, nk, n.NodeKey)
	require.True(t, n.DiscoKey.IsZero())
	require.NotNil(t, n.IPv4)
	require.Equal(t, "100.90.150.122", n.IPv4.String())
	require.NotNil(t, n.IPv6)
	require.Equal(t, "fd7a:115c:a1e0::9", n.IPv6.String())
	require.Equal(t, "wg-ca-17-v2", n.Hostname)
	require.Equal(t, "acme", n.Namespace)
	require.Equal(t, "acme.net", n.NetworkDomain)
	require.Equal(t, "cli", n.RegisterMethod)
	require.NotNil(t, n.Expiry)
	require.True(t, n.Expiry.Equal(expiry))
	require.Nil(t, n.LastSeen)
	require.NotNil(t, n.IsOnline)
	require.True(t, *n.IsOnline)
	require.Equal(t, []string{"tag:gateway"}, n.Tags)
	require.NotNil(t, n.IsWireguardOnly)
	require.True(t, *n.IsWireguardOnly)
	require.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("134.199.212.130:54458")}, n.Endpoints)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}, n.ApprovedRoutes,
		"only enabled routes become approved routes")
	require.Len(t, n.Capabilities, 1)
	require.Equal(t, "relay", n.Capabilities[0].Name)
	require.Equal(t, "acme", n.Capabilities[0].Namespace)
}

func TestParseProtoNodeForCreateRejectsBadInput(t *testing.T) {
	_, err := ParseProtoNodeForCreate(nil)
	require.Error(t, err)

	_, err = ParseProtoNodeForCreate(&v1.Node{Name: "x", IpAddresses: []string{"not-an-ip"}})
	require.Error(t, err)

	_, err = ParseProtoNodeForCreate(&v1.Node{Name: "x", Endpoints: []string{"1.2.3.4"}})
	require.Error(t, err, "endpoint without a port")

	_, err = ParseProtoNodeForCreate(&v1.Node{Name: "x", MachineKey: "mkey:zz"})
	require.Error(t, err)
}

func TestParseProtoEndpointsAndRoutesEmpty(t *testing.T) {
	eps, err := ParseProtoEndpoints(nil)
	require.NoError(t, err)
	require.Nil(t, eps)

	routes, err := ApprovedRoutesFromProtoRouteSpecs(nil)
	require.NoError(t, err)
	require.Nil(t, routes)
}
