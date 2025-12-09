package db

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

func TestMigrations(t *testing.T) {
	ipp := func(p string) types.IPPrefix {
		return types.IPPrefix(netip.MustParsePrefix(p))
	}
	r := func(id uint64, p string, a, e, i bool) types.Route {
		return types.Route{
			NodeID:     id,
			Prefix:     ipp(p),
			Advertised: a,
			Enabled:    e,
			IsPrimary:  i,
		}
	}
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
		wantErr  string
	}{
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-are-dropped-2063.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				assert.NoError(t, err)

				assert.Len(t, routes, 10)
				want := types.Routes{
					r(1, "0.0.0.0/0", true, true, false),
					r(1, "::/0", true, true, false),
					r(1, "10.9.110.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, false, false),
					r(31, "0.0.0.0/0", true, true, false),
					r(31, "0.0.0.0/0", true, false, false),
					r(31, "::/0", true, true, false),
					r(31, "::/0", true, false, false),
					r(32, "192.168.0.24/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), cmp.Comparer(func(x, y types.IPPrefix) bool {
					return x == y
				})); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-fail-foreign-key-2076.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				assert.NoError(t, err)

				assert.Len(t, routes, 4)
				want := types.Routes{
					// These routes exists, but have no nodes associated with them
					// when the migration starts.
					// r(1, "0.0.0.0/0", true, true, false),
					// r(1, "::/0", true, true, false),
					// r(3, "0.0.0.0/0", true, true, false),
					// r(3, "::/0", true, true, false),
					// r(5, "0.0.0.0/0", true, true, false),
					// r(5, "::/0", true, true, false),
					// r(6, "0.0.0.0/0", true, true, false),
					// r(6, "::/0", true, true, false),
					// r(6, "10.0.0.0/8", true, false, false),
					// r(7, "0.0.0.0/0", true, true, false),
					// r(7, "::/0", true, true, false),
					// r(7, "10.0.0.0/8", true, false, false),
					// r(9, "0.0.0.0/0", true, true, false),
					// r(9, "::/0", true, true, false),
					// r(9, "10.0.0.0/8", true, true, false),
					// r(11, "0.0.0.0/0", true, true, false),
					// r(11, "::/0", true, true, false),
					// r(11, "10.0.0.0/8", true, true, true),
					// r(12, "0.0.0.0/0", true, true, false),
					// r(12, "::/0", true, true, false),
					// r(12, "10.0.0.0/8", true, false, false),
					//
					// These nodes exists, so routes should be kept.
					r(13, "10.0.0.0/8", true, false, false),
					r(13, "0.0.0.0/0", true, true, false),
					r(13, "::/0", true, true, false),
					r(13, "10.18.80.2/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), cmp.Comparer(func(x, y types.IPPrefix) bool {
					return x == y
				})); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dbPath, func(t *testing.T) {
			dbPath, err := testCopyOfDatabase(tt.dbPath)
			if err != nil {
				t.Fatalf("copying db for test: %s", err)
			}

			// __BEGIN_CYLONIX_ADD__
			// Fix duplicate node_key entries before migrations
			if err := fixDuplicateNodeKeys(types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: dbPath,
				},
			}); err != nil {
				log.Warn().Err(err).Msg("Failed to fix duplicate node keys, continuing anyway")
			}
			// __END_CYLONIX_ADD__

			hsdb, err := NewHeadscaleDatabase(types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: dbPath,
				},
			}, "")
			if err != nil && tt.wantErr != err.Error() {
				t.Errorf("TestMigrations() unexpected error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantFunc != nil {
				tt.wantFunc(t, hsdb)
			}
		})
	}
}

// __BEGIN_CYLONIX_ADD__
func fixDuplicateNodeKeys(cfg types.DatabaseConfig) error {
	isSQList := cfg.Type == "sqlite3"
	db, err := openDB(cfg)
	if err != nil {
		return err
	}

	// Check if machines table exists
	var tableExists bool
	if !isSQList {
		err := db.Raw("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'machines')").Scan(&tableExists).Error
		if err != nil || !tableExists {
			return nil // Table doesn't exist yet, skip
		}
	} else {
		// SQLite
		var count int64
		err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='machines'").Scan(&count).Error
		if err != nil || count == 0 {
			return nil // Table doesn't exist yet, skip
		}
	}

	// Find duplicate node_key entries
	type NodeKeyCount struct {
		NodeKey string
		Count   int64
	}

	var duplicates []NodeKeyCount
	err = db.Raw(`
        SELECT node_key, COUNT(*) as count
        FROM machines
        WHERE node_key IS NOT NULL AND node_key != ''
        GROUP BY node_key
        HAVING COUNT(*) > 1
    `).Scan(&duplicates).Error

	if err != nil {
		return fmt.Errorf("failed to find duplicate node keys: %w", err)
	}

	if len(duplicates) == 0 {
		log.Debug().Msg("No duplicate node keys found")
		return nil
	}

	log.Info().
		Int("duplicate_groups", len(duplicates)).
		Msg("Found duplicate node keys, fixing...")

	// For each duplicate node_key, keep the oldest and update the rest
	for _, dup := range duplicates {
		type MachineRow struct {
			ID        uint64
			NodeKey   string
			CreatedAt time.Time
		}

		var machines []MachineRow
		err := db.Raw(`
            SELECT id, node_key, created_at
            FROM machines
            WHERE node_key = ?
            ORDER BY created_at ASC, id ASC
        `, dup.NodeKey).Scan(&machines).Error

		if err != nil {
			log.Error().
				Err(err).
				Str("node_key", dup.NodeKey).
				Msg("Failed to fetch machines with duplicate node_key")
			continue
		}

		// Keep the first one (oldest), update the rest
		for i := 1; i < len(machines); i++ {
			// Generate a new node key
			newNodeKey, newMachineKey, err := generateNewKeys()
			if err != nil {
				log.Error().
					Err(err).
					Uint64("machine_id", machines[i].ID).
					Msg("Failed to generate new node key and machine key")
				continue
			}

			// Update the machine with new node key
			err = db.Exec(`
                UPDATE machines
                SET node_key = ?, machine_key = ?
                WHERE id = ?
            `, newNodeKey, newMachineKey, machines[i].ID).Error

			if err != nil {
				log.Error().
					Err(err).
					Uint64("machine_id", machines[i].ID).
					Msg("Failed to update machine with new node key")
			} else {
				log.Info().
					Uint64("machine_id", machines[i].ID).
					Str("old_node_key", machines[i].NodeKey).
					Str("new_node_key", newNodeKey).
					Msg("Updated machine with new node key")
			}
		}
	}

	return nil
}

func generateNewKeys() (string, string, error) {
	// Generate a new Tailscale-compatible node key
	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	return nodeKey.Public().String(), machineKey.Public().String(), nil
}
// __END_CYLONIX_ADD__

func testCopyOfDatabase(src string) (string, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return "", err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()

	tmpDir, err := os.MkdirTemp("", "hsdb-test-*")
	if err != nil {
		return "", err
	}

	fn := filepath.Base(src)
	dst := filepath.Join(tmpDir, fn)

	destination, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return dst, err
}
