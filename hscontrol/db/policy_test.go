// Copyright (c) Cylonix Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListLatestPolicyPerTailnet exercises the cylonix-only DB helper that
// surfaces the latest row per (namespace, network) pair from the
// policies table. Because SetPolicy inserts (never updates), the table
// accumulates one row per edit; the helper is what lets ReloadPolicy
// pick out the current state per tailnet without dragging in stale
// history.
//
// This is the regression test for the multi-tenant ReloadPolicy
// startup-load path.
func TestListLatestPolicyPerTailnet(t *testing.T) {
	hsdb := dbForTest(t)
	defer hsdb.Close()

	// Empty DB — should return zero rows, not an error.
	rows, err := hsdb.ListLatestPolicyPerTailnet()
	require.NoError(t, err)
	assert.Empty(t, rows, "empty policies table should yield no rows")

	// Insert two distinct tailnets, plus a second edit for one of
	// them, plus a legacy unscoped row that must be excluded.
	mustInsert := func(data, namespace, network string) {
		t.Helper()
		_, err := hsdb.SetPolicy(data, namespace, network)
		require.NoError(t, err, "SetPolicy(%q, %q, %q)", data, namespace, network)
	}

	mustInsert(`{"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}]}`, "tenantA", "domainA")
	mustInsert(`{"acls": [{"action":"accept","src":["*"],"dst":["*:443"]}]}`, "tenantB", "domainB")
	mustInsert(`{"acls": []}`, "tenantA", "domainA") // newer A row — should win
	mustInsert(`{"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}]}`, "", "")

	rows, err = hsdb.ListLatestPolicyPerTailnet()
	require.NoError(t, err)
	require.Len(t, rows, 2, "expected one row per (namespace, network) pair, excluding the unscoped row")

	// Stabilise output order so assertions don't depend on the DB
	// driver's row ordering.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Namespace+rows[i].Network < rows[j].Namespace+rows[j].Network
	})

	assert.Equal(t, "tenantA", rows[0].Namespace)
	assert.Equal(t, "domainA", rows[0].Network)
	assert.Equal(t, `{"acls": []}`, rows[0].Data, "tenantA latest row should be the newer (empty acls) write, not the original")

	assert.Equal(t, "tenantB", rows[1].Namespace)
	assert.Equal(t, "domainB", rows[1].Network)
}
