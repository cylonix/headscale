package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect" // __CYLONIX_ADD__ used by ListWithOptions
	"slices"
	"strconv"
	"strings" // __CYLONIX_ADD__ used by ListWithOptions
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/squibble"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"tailscale.com/net/tsaddr"
	"zgo.at/zcache/v2"
)

//go:embed schema.sql
var dbSchema string

func init() {
	schema.RegisterSerializer("text", TextSerialiser{})
}

var errDatabaseNotSupported = errors.New("database type not supported")

var errForeignKeyConstraintsViolated = errors.New("foreign key constraints violated")

const (
	maxIdleConns       = 100
	maxOpenConns       = 100
	contextTimeoutSecs = 10
)

type HSDatabase struct {
	DB       *gorm.DB
	cfg      *types.Config
	regCache *zcache.Cache[types.RegistrationID, types.RegisterNode]
}

// NewHeadscaleDatabase creates a new database connection and runs migrations.
// It accepts the full configuration to allow migrations access to policy settings.
func NewHeadscaleDatabase(
	cfg *types.Config,
	regCache *zcache.Cache[types.RegistrationID, types.RegisterNode],
) (*HSDatabase, error) {
	dbConn, err := openDB(cfg.Database)
	if err != nil {
		return nil, err
	}

	migrations := gormigrate.New(
		dbConn,
		gormigrate.DefaultOptions,
		[]*gormigrate.Migration{
			// New migrations must be added as transactions at the end of this list.
			// Migrations start from v0.25.0. If upgrading from v0.24.x or earlier,
			// you must first upgrade to v0.25.1 before upgrading to this version.

			// v0.25.0
			{
				// Add a constraint to routes ensuring they cannot exist without a node.
				ID: "202501221827",
				Migrate: func(tx *gorm.DB) error {
					// __BEGIN_CYLONIX_ADD__
					// Cylonix databases predate v0.25 and still carry the pre-rename
					// schema (namespaces/machines/etc.). Run the legacy renames and
					// per-node cleanup before the upstream v0.25 route cleanup so the
					// rest of the migration chain operates on the expected shape.
					if cfg.Database.Type == types.DatabasePostgres {
						tx.Exec(`create extension if not exists "uuid-ossp";`)
					}

					_ = tx.Migrator().RenameTable("namespaces", "users")

					// the big rename from Machine to Node
					_ = tx.Migrator().RenameTable("machines", "nodes")
					_ = tx.Migrator().
						RenameColumn(&types.Route{}, "machine_id", "node_id")

					if err := tx.AutoMigrate(types.User{}); err != nil {
						return err
					}

					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "namespace_id", "user_id")
					_ = tx.Migrator().
						RenameColumn(&types.PreAuthKey{}, "namespace_id", "user_id")

					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "ip_address", "ip_addresses")
					_ = tx.Migrator().RenameColumn(&types.Node{}, "name", "hostname")

					// GivenName is used as the primary source of DNS names, make sure
					// the field is populated and normalized if it was not when the
					// node was registered.
					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "nickname", "given_name")

					dbConn.Model(&types.Node{}).Where("auth_key_id = ?", 0).Update("auth_key_id", nil)

					// If the Node table has a column for registered,
					// find all occurrences of "false" and drop them. Then
					// remove the column.
					if tx.Migrator().HasColumn(&types.Node{}, "registered") {
						log.Info().
							Msg(`Database has legacy "registered" column in node, removing...`)

						nodes := types.Nodes{}
						if err := tx.Not("registered").Find(&nodes).Error; err != nil {
							log.Error().Err(err).Msg("Error accessing db")
						}

						for _, node := range nodes {
							log.Info().
								Str("node", node.Hostname).
								Str("machine_key", node.MachineKey.ShortString()).
								Msg("Deleting unregistered node")
							if err := tx.Delete(&types.Node{}, node.ID).Error; err != nil {
								logEvent := log.Error().
									Err(err).
									Str("node", node.Hostname).
									Str("machine_key", node.MachineKey.ShortString()).
									Str("namespace", node.Namespace)
								if node.User != nil {
									logEvent = logEvent.Str("user", node.User.Name)
								}
								logEvent.Msg("Error deleting unregistered node")
							}
						}

						if err := tx.Migrator().DropColumn(&types.Node{}, "registered"); err != nil {
							log.Error().Err(err).Msg("Error dropping registered column")
						}
					}
					// __END_CYLONIX_ADD__

					// Remove any invalid routes associated with a node that does not exist.
					if tx.Migrator().HasTable(&types.Route{}) && tx.Migrator().HasTable(&types.Node{}) {
						err := tx.Exec("delete from routes where node_id not in (select id from nodes)").Error
						if err != nil {
							return err
						}
					}

					// Remove any invalid routes without a node_id.
					if tx.Migrator().HasTable(&types.Route{}) {
						err := tx.Exec("delete from routes where node_id is null").Error
						if err != nil {
							return err
						}
					}

					err := tx.AutoMigrate(&types.Route{})
					if err != nil {
						return fmt.Errorf("automigrating types.Route: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back constraint so you cannot delete preauth keys that
			// is still used by a node.
			{
				ID: "202501311657",
				Migrate: func(tx *gorm.DB) error {
					err := tx.AutoMigrate(&types.PreAuthKey{})
					if err != nil {
						return fmt.Errorf("automigrating types.PreAuthKey: %w", err)
					}
					err = tx.AutoMigrate(&types.Node{})
					if err != nil {
						return fmt.Errorf("automigrating types.Node: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Ensure there are no nodes referring to a deleted preauthkey.
			{
				ID: "202502070949",
				Migrate: func(tx *gorm.DB) error {
					if tx.Migrator().HasTable(&types.PreAuthKey{}) {
						err := tx.Exec(`
UPDATE nodes
SET auth_key_id = NULL
WHERE auth_key_id IS NOT NULL
AND auth_key_id NOT IN (
    SELECT id FROM pre_auth_keys
);
							`).Error
						if err != nil {
							return fmt.Errorf("setting auth_key to null on nodes with non-existing keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.26.0
			// Migrate all routes from the Route table to the new field ApprovedRoutes
			// in the Node table. Then drop the Route table.
			{
				ID: "202502131714",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.Node{}, "approved_routes") {
						err := tx.Migrator().AddColumn(&types.Node{}, "approved_routes")
						if err != nil {
							return fmt.Errorf("adding column types.Node: %w", err)
						}
					}

					nodeRoutes := map[uint64][]netip.Prefix{}

					var routes []types.Route
					err = tx.Find(&routes).Error
					if err != nil {
						return fmt.Errorf("fetching routes: %w", err)
					}

					for _, route := range routes {
						if route.Enabled {
							nodeRoutes[route.NodeID] = append(nodeRoutes[route.NodeID], route.Prefix)
						}
					}

					for nodeID, routes := range nodeRoutes {
						tsaddr.SortPrefixes(routes)
						routes = slices.Compact(routes)

						data, err := json.Marshal(routes)

						err = tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", data).Error
						if err != nil {
							return fmt.Errorf("saving approved routes to new column: %w", err)
						}
					}

					// __BEGIN_CYLONIX_MOD__
					// Shadow-keep: rename `routes` to `routes_archive` instead of
					// dropping so we can review/rollback during the manage-v2
					// cutover. Upstream drops the table here; cylonix keeps the
					// row data for conservative migration. Drop later once the
					// v2 cutover is verified.
					if tx.Migrator().HasTable(&types.Route{}) {
						// Use raw SQL because RenameTable doesn't accept string
						// targets across both sqlite and postgres reliably.
						if err := tx.Exec("ALTER TABLE routes RENAME TO routes_archive").Error; err != nil {
							// If rename fails (e.g., routes_archive already exists
							// from a replay), fall back to drop so the migration
							// is idempotent.
							log.Warn().Err(err).Msg("routes→routes_archive rename failed; falling back to drop")
							_ = tx.Migrator().DropTable(&types.Route{})
						}
					}
					// __END_CYLONIX_MOD__

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202502171819",
				Migrate: func(tx *gorm.DB) error {
					// This migration originally removed the last_seen column
					// from the node table, but it was added back in
					// 202505091439.
					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back last_seen column to node table.
			{
				ID: "202505091439",
				Migrate: func(tx *gorm.DB) error {
					// Add back last_seen column to node table if it does not exist.
					// This is a workaround for the fact that the last_seen column
					// was removed in the 202502171819 migration, but only for some
					// beta testers.
					if !tx.Migrator().HasColumn(&types.Node{}, "last_seen") {
						_ = tx.Migrator().AddColumn(&types.Node{}, "last_seen")
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Fix the provider identifier for users that have a double slash in the
			// provider identifier.
			{
				ID: "202505141324",
				Migrate: func(tx *gorm.DB) error {
					users, err := ListUsers(tx)
					if err != nil {
						return fmt.Errorf("listing users: %w", err)
					}

					for _, user := range users {
						user.ProviderIdentifier.String = types.CleanIdentifier(user.ProviderIdentifier.String)

						err := tx.Save(user).Error
						if err != nil {
							return fmt.Errorf("saving user: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.27.0
			// Schema migration to ensure all tables match the expected schema.
			// This migration recreates all tables to match the exact structure in schema.sql,
			// preserving all data during the process.
			// Only SQLite will be migrated for consistency.
			{
				ID: "202507021200",
				Migrate: func(tx *gorm.DB) error {
					// Only run on SQLite
					if cfg.Database.Type != types.DatabaseSqlite {
						log.Info().Msg("Skipping schema migration on non-SQLite database")
						return nil
					}

					log.Info().Msg("Starting schema recreation with table renaming")

					// Rename existing tables to _old versions
					tablesToRename := []string{"users", "pre_auth_keys", "api_keys", "nodes", "policies"}

					// Check if routes table exists and drop it (should have been migrated already)
					var routesExists bool
					err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='routes'").Row().Scan(&routesExists)
					if err == nil && routesExists {
						log.Info().Msg("Dropping leftover routes table")
						if err := tx.Exec("DROP TABLE routes").Error; err != nil {
							return fmt.Errorf("dropping routes table: %w", err)
						}
					}

					// Drop all indexes first to avoid conflicts
					indexesToDrop := []string{
						"idx_users_deleted_at",
						"idx_provider_identifier",
						"idx_name_provider_identifier",
						"idx_name_no_provider_identifier",
						"idx_api_keys_prefix",
						"idx_policies_deleted_at",
					}

					for _, index := range indexesToDrop {
						_ = tx.Exec("DROP INDEX IF EXISTS " + index).Error
					}

					for _, table := range tablesToRename {
						// Check if table exists before renaming
						var exists bool
						err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Row().Scan(&exists)
						if err != nil {
							return fmt.Errorf("checking if table %s exists: %w", table, err)
						}

						if exists {
							// Drop old table if it exists from previous failed migration
							_ = tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error

							// Rename current table to _old
							if err := tx.Exec("ALTER TABLE " + table + " RENAME TO " + table + "_old").Error; err != nil {
								return fmt.Errorf("renaming table %s to %s_old: %w", table, table, err)
							}
						}
					}

					// Create new tables with correct schema
					tableCreationSQL := []string{
						`CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
						`CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,
  created_at datetime,
  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
)`,
						`CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,
  created_at datetime
)`,
						`CREATE TABLE nodes(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,
  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  hostname text,
  given_name varchar(63),
  user_id integer,
  register_method text,
  forced_tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime,
  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
)`,
						`CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
					}

					for _, createSQL := range tableCreationSQL {
						if err := tx.Exec(createSQL).Error; err != nil {
							return fmt.Errorf("creating new table: %w", err)
						}
					}

					// Copy data directly using SQL
					dataCopySQL := []string{
						`INSERT INTO users (id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
             SELECT id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at
             FROM users_old`,

						`INSERT INTO pre_auth_keys (id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at)
             SELECT id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at
             FROM pre_auth_keys_old`,

						`INSERT INTO api_keys (id, prefix, hash, expiration, last_seen, created_at)
             SELECT id, prefix, hash, expiration, last_seen, created_at
             FROM api_keys_old`,

						`INSERT INTO nodes (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
             SELECT id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at
             FROM nodes_old`,

						`INSERT INTO policies (id, data, created_at, updated_at, deleted_at)
             SELECT id, data, created_at, updated_at, deleted_at
             FROM policies_old`,
					}

					for _, copySQL := range dataCopySQL {
						if err := tx.Exec(copySQL).Error; err != nil {
							return fmt.Errorf("copying data: %w", err)
						}
					}

					// Create indexes
					indexes := []string{
						"CREATE INDEX idx_users_deleted_at ON users(deleted_at)",
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(
  provider_identifier
) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(
  name,
  provider_identifier
)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(
  name
) WHERE provider_identifier IS NULL`,
						"CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)",
						"CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)",
					}

					for _, indexSQL := range indexes {
						if err := tx.Exec(indexSQL).Error; err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					// Drop old tables only after everything succeeds
					for _, table := range tablesToRename {
						if err := tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error; err != nil {
							log.Warn().Str("table", table+"_old").Err(err).Msg("Failed to drop old table, but migration succeeded")
						}
					}

					log.Info().Msg("Schema recreation completed successfully")

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// __BEGIN_CYLONIX_ADD__
			// Cylonix data-preserving migration: copy existing
			// pre_auth_key_acl_tags rows into the new pre_auth_keys.tags JSON
			// column BEFORE the v0.27.1 migration drops the legacy table.
			// Cylonix production DBs may have PreAuthKeys with ACL tags
			// configured via the old separate table. Without this copy, those
			// tags would be silently lost on cutover.
			//
			// The ID is intentionally one less than the drop migration's ID
			// (202510311551) so that gormigrate's lexicographic ordering runs
			// the preservation step first.
			{
				ID: "202510311550-cylonix-preserve-preauth-acl-tags",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasTable("pre_auth_key_acl_tags") {
						return nil // already dropped or never existed
					}
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "tags") {
						if err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "tags"); err != nil {
							return fmt.Errorf("adding tags column: %w", err)
						}
					}
					rows, err := tx.Raw(`SELECT pre_auth_key_id, tag FROM pre_auth_key_acl_tags`).Rows()
					if err != nil {
						return fmt.Errorf("reading legacy acl tags: %w", err)
					}
					tagsByID := map[uint64][]string{}
					for rows.Next() {
						var id uint64
						var tag string
						if err := rows.Scan(&id, &tag); err != nil {
							rows.Close()
							return err
						}
						tagsByID[id] = append(tagsByID[id], tag)
					}
					rows.Close()
					for id, tags := range tagsByID {
						data, err := json.Marshal(tags)
						if err != nil {
							return fmt.Errorf("marshaling tags for pak %d: %w", id, err)
						}
						if err := tx.Exec(
							`UPDATE pre_auth_keys SET tags = ? WHERE id = ?`,
							string(data), id,
						).Error; err != nil {
							return fmt.Errorf("updating pak %d: %w", id, err)
						}
					}
					log.Info().
						Int("preauth_keys_with_tags", len(tagsByID)).
						Msg("preserved legacy pre_auth_key_acl_tags into pre_auth_keys.tags")
					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// __END_CYLONIX_ADD__

			// v0.27.1
			{
				// Drop all tables that are no longer in use and have existed.
				// They potentially still are present from broken migrations in the
				// past.
				ID: "202510311551",
				Migrate: func(tx *gorm.DB) error {
					// __BEGIN_CYLONIX_MOD__
					// Shadow-keep: drop only tables that cylonix is certain aren't
					// in use. `routes` is preserved as `routes_archive` by the
					// earlier migration; do not re-drop it here. `kvs` is unused.
					// `pre_auth_key_acl_tags` was just drained by the immediately-
					// preceding migration into the new pre_auth_keys.tags JSON
					// column. The pre-v0.20 tables (`namespaces`, `machines`,
					// `shared_machines`) should never have existed in a cylonix DB
					// (fork diverged at v0.23.0-beta3+8) but we still drop them
					// defensively if present.
					for _, oldTable := range []string{"namespaces", "machines", "shared_machines", "kvs", "pre_auth_key_acl_tags"} {
						err := tx.Migrator().DropTable(oldTable)
						if err != nil {
							log.Trace().Str("table", oldTable).
								Err(err).
								Msg("Error dropping old table, continuing...")
						}
					}
					// __END_CYLONIX_MOD__

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// Drop all indices that are no longer in use and has existed.
				// They potentially still present from broken migrations in the past.
				// They should all be cleaned up by the db engine, but we are a bit
				// conservative to ensure all our previous mess is cleaned up.
				ID: "202511101554-drop-old-idx",
				Migrate: func(tx *gorm.DB) error {
					for _, oldIdx := range []struct{ name, table string }{
						{"idx_namespaces_deleted_at", "namespaces"},
						{"idx_routes_deleted_at", "routes"},
						{"idx_shared_machines_deleted_at", "shared_machines"},
					} {
						err := tx.Migrator().DropIndex(oldIdx.table, oldIdx.name)
						if err != nil {
							log.Trace().
								Str("index", oldIdx.name).
								Str("table", oldIdx.table).
								Err(err).
								Msg("Error dropping old index, continuing...")
						}
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},

			// Migrations **above** this points will be REMOVED in version **0.29.0**
			// This is to clean up a lot of old migrations that is seldom used
			// and carries a lot of technical debt.
			// Any new migrations should be added after the comment below and follow
			// the rules it sets out.

			// From this point, the following rules must be followed:
			// - NEVER use gorm.AutoMigrate, write the exact migration steps needed
			// - AutoMigrate depends on the struct staying exactly the same, which it won't over time.
			// - Never write migrations that requires foreign keys to be disabled.
			// - ALL errors in migrations must be handled properly.

			{
				// Add columns for prefix and hash for pre auth keys, implementing
				// them with the same security model as api keys.
				ID: "202511011637-preauthkey-bcrypt",
				Migrate: func(tx *gorm.DB) error {
					// Check and add prefix column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "prefix") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "prefix")
						if err != nil {
							return fmt.Errorf("adding prefix column: %w", err)
						}
					}

					// Check and add hash column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "hash") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "hash")
						if err != nil {
							return fmt.Errorf("adding hash column: %w", err)
						}
					}

					// Create partial unique index to allow multiple legacy keys (NULL/empty prefix)
					// while enforcing uniqueness for new bcrypt-based keys
					err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''").Error
					if err != nil {
						return fmt.Errorf("creating prefix index: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202511122344-remove-newline-index",
				Migrate: func(tx *gorm.DB) error {
					// Reformat multi-line indexes to single-line for consistency
					// This migration drops and recreates the three user identity indexes
					// to match the single-line format expected by schema validation

					// Drop existing multi-line indexes
					dropIndexes := []string{
						`DROP INDEX IF EXISTS idx_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_no_provider_identifier`,
					}

					for _, dropSQL := range dropIndexes {
						err := tx.Exec(dropSQL).Error
						if err != nil {
							return fmt.Errorf("dropping index: %w", err)
						}
					}

					// Recreate indexes in single-line format
					createIndexes := []string{
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
					}

					for _, createSQL := range createIndexes {
						err := tx.Exec(createSQL).Error
						if err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Rename forced_tags column to tags in nodes table.
				// This must run after migration 202505141324 which creates tables with forced_tags.
				ID: "202511131445-node-forced-tags-to-tags",
				Migrate: func(tx *gorm.DB) error {
					m := tx.Migrator()
					hasForced := m.HasColumn(&types.Node{}, "forced_tags")
					hasTags := m.HasColumn(&types.Node{}, "tags")

					// __BEGIN_CYLONIX_MOD__
					// On the cylonix v1 upgrade lineage an earlier AutoMigrate
					// (202501311657) adds an empty `tags` column from the v0.28
					// Node struct while the legacy `forced_tags` still holds the
					// data, so a plain RenameColumn fails with "column tags
					// already exists". forced_tags is the source of truth here,
					// so drop the empty AutoMigrate-created tags column before
					// renaming. On a fresh/already-migrated DB (no forced_tags)
					// this whole migration is a no-op.
					if hasForced && hasTags {
						if err := m.DropColumn(&types.Node{}, "tags"); err != nil {
							return fmt.Errorf("dropping pre-existing tags column before rename: %w", err)
						}
					}
					if !hasForced {
						// Already migrated (tags exists) or neither column
						// exists; nothing to rename.
						return nil
					}
					// __END_CYLONIX_MOD__

					// Rename the column from forced_tags to tags
					err := tx.Migrator().RenameColumn(&types.Node{}, "forced_tags", "tags")
					if err != nil {
						return fmt.Errorf("renaming forced_tags to tags: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Migrate RequestTags from host_info JSON to tags column.
				// In 0.27.x, tags from --advertise-tags (ValidTags) were stored only in
				// host_info.RequestTags, not in the tags column (formerly forced_tags).
				// This migration validates RequestTags against the policy's tagOwners
				// and merges validated tags into the tags column.
				// Fixes: https://github.com/juanfont/headscale/issues/3006
				ID: "202601121700-migrate-hostinfo-request-tags",
				Migrate: func(tx *gorm.DB) error {
					// 1. Load policy from file or database based on configuration
					policyData, err := PolicyBytes(tx, cfg)
					if err != nil {
						log.Warn().Err(err).Msg("Failed to load policy, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					if len(policyData) == 0 {
						log.Info().Msg("No policy found, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					// 2. Load users and nodes to create PolicyManager
					users, err := ListUsers(tx)
					if err != nil {
						return fmt.Errorf("loading users for RequestTags migration: %w", err)
					}

					nodes, err := ListNodes(tx)
					if err != nil {
						return fmt.Errorf("loading nodes for RequestTags migration: %w", err)
					}

					// 3. Create PolicyManager (handles HuJSON parsing, groups, nested tags, etc.)
					polMan, err := policy.NewPolicyManager(policyData, users, nodes.ViewSlice())
					if err != nil {
						log.Warn().Err(err).Msg("Failed to parse policy, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					// 4. Process each node
					for _, node := range nodes {
						if node.Hostinfo == nil {
							continue
						}

						requestTags := node.Hostinfo.RequestTags
						if len(requestTags) == 0 {
							continue
						}

						existingTags := node.Tags

						var validatedTags, rejectedTags []string

						nodeView := node.View()

						for _, tag := range requestTags {
							if polMan.NodeCanHaveTag(nodeView, tag) {
								if !slices.Contains(existingTags, tag) {
									validatedTags = append(validatedTags, tag)
								}
							} else {
								rejectedTags = append(rejectedTags, tag)
							}
						}

						if len(validatedTags) == 0 {
							if len(rejectedTags) > 0 {
								log.Debug().
									Uint64("node.id", uint64(node.ID)).
									Str("node.name", node.Hostname).
									Strs("rejected_tags", rejectedTags).
									Msg("RequestTags rejected during migration (not authorized)")
							}

							continue
						}

						mergedTags := append(existingTags, validatedTags...)
						slices.Sort(mergedTags)
						mergedTags = slices.Compact(mergedTags)

						tagsJSON, err := json.Marshal(mergedTags)
						if err != nil {
							return fmt.Errorf("serializing merged tags for node %d: %w", node.ID, err)
						}

						err = tx.Exec("UPDATE nodes SET tags = ? WHERE id = ?", string(tagsJSON), node.ID).Error
						if err != nil {
							return fmt.Errorf("updating tags for node %d: %w", node.ID, err)
						}

						log.Info().
							Uint64("node.id", uint64(node.ID)).
							Str("node.name", node.Hostname).
							Strs("validated_tags", validatedTags).
							Strs("rejected_tags", rejectedTags).
							Strs("existing_tags", existingTags).
							Strs("merged_tags", mergedTags).
							Msg("Migrated validated RequestTags from host_info to tags column")
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// __BEGIN_CYLONIX_ADD__
			{
				ID: "202412031400",
				// Migrate tables with additional columns.
				Migrate: func(tx *gorm.DB) error {
					return tx.AutoMigrate(
						&types.APIKey{},
						&types.Node{},
						&types.Policy{},
						&types.PreAuthKey{},
						&types.Route{},
						&types.User{},
						&types.Capability{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202505161000",
				Migrate: func(tx *gorm.DB) error {
					log.Info().Msg(`
						Migrating database to add NetworkDomain and update
						GivenName unique index to Node.`)
					return tx.AutoMigrate(
						&types.Node{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "2025051201000",
				Migrate: func(tx *gorm.DB) error {
					log.Info().Msg(`
						Migrating database to add Network for network domain.
						`)
					return tx.AutoMigrate(
						&types.User{},
						&types.APIKey{},
						&types.Route{},
						&types.Policy{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202507211100",
				Migrate: func(tx *gorm.DB) error {
					log.Info().Msg(`
						Migrating database to add pre auth key description.
						`)
					return tx.AutoMigrate(
						&types.PreAuthKey{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202511301100",
				Migrate: func(tx *gorm.DB) error {
					log.Info().Msg(`
						Migrating database to add node health string.
						`)
					return tx.AutoMigrate(
						&types.Node{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202601051100",
				Migrate: func(tx *gorm.DB) error {
					log.Info().Msg(`
						Migrating database to add node shared-to relations.
						`)
					return tx.AutoMigrate(
						&types.Node{},
					)
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Cylonix `nodes_network_domain_given_name` used to be a plain
				// compound unique index. That collides on the very common
				// fixture shape where multiple nodes have empty GivenName in
				// an empty NetworkDomain. Reshape it as a PARTIAL index so
				// only non-empty GivenNames enforce uniqueness, which matches
				// production semantics (GivenName is always populated during
				// registration) while allowing test fixtures / mid-insert
				// transient states to coexist.
				ID: "202604240001-cylonix-given-name-partial-index",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(`DROP INDEX IF EXISTS "nodes_network_domain_given_name"`).Error; err != nil {
						return err
					}
					return tx.Exec(
						`CREATE UNIQUE INDEX "nodes_network_domain_given_name" ` +
							`ON nodes(given_name, network_domain) ` +
							`WHERE given_name != ''`,
					).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// __END_CYLONIX_ADD__
		},
	)

	migrations.InitSchema(func(tx *gorm.DB) error {
		// Create all tables using AutoMigrate
		err := tx.AutoMigrate(
			&types.User{},
			&types.PreAuthKey{},
			&types.APIKey{},
			&types.Node{},
			&types.Policy{},
		)
		if err != nil {
			return err
		}

		// Drop all indexes (both GORM-created and potentially pre-existing ones)
		// to ensure we can recreate them in the correct format
		dropIndexes := []string{
			`DROP INDEX IF EXISTS "idx_users_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_api_keys_prefix"`,
			`DROP INDEX IF EXISTS "idx_policies_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_no_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_pre_auth_keys_prefix"`,
		}

		for _, dropSQL := range dropIndexes {
			err := tx.Exec(dropSQL).Error
			if err != nil {
				return err
			}
		}

		// Recreate indexes without backticks to match schema.sql format
		indexes := []string{
			`CREATE INDEX idx_users_deleted_at ON users(deleted_at)`,
			`CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)`,
			`CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)`,
			`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
			`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
			`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
			`CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''`,
		}

		for _, indexSQL := range indexes {
			err := tx.Exec(indexSQL).Error
			if err != nil {
				return err
			}
		}

		// __BEGIN_CYLONIX_ADD__
		// Cylonix partial unique index on (given_name, network_domain). See
		// the 202604240001 migration for rationale; we duplicate it here so
		// fresh-install InitSchema matches the post-migration shape.
		if err := tx.Exec(`DROP INDEX IF EXISTS "nodes_network_domain_given_name"`).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE UNIQUE INDEX "nodes_network_domain_given_name" ON nodes(given_name, network_domain) WHERE given_name != ''`).Error; err != nil {
			return err
		}
		// __END_CYLONIX_ADD__

		return nil
	})

	err = runMigrations(cfg.Database, dbConn, migrations)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Validate that the schema ends up in the expected state.
	// This is currently only done on sqlite as squibble does not
	// support Postgres and we use our sqlite schema as our source of
	// truth.
	if cfg.Database.Type == types.DatabaseSqlite {
		sqlConn, err := dbConn.DB()
		if err != nil {
			return nil, fmt.Errorf("getting DB from gorm: %w", err)
		}

		// or else it blocks...
		sqlConn.SetMaxIdleConns(maxIdleConns)
		sqlConn.SetMaxOpenConns(maxOpenConns)
		defer sqlConn.SetMaxIdleConns(1)
		defer sqlConn.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), contextTimeoutSecs*time.Second)
		defer cancel()

		opts := squibble.DigestOptions{
			IgnoreTables: []string{
				// Litestream tables, these are inserted by
				// litestream and not part of our schema
				// https://litestream.io/how-it-works
				"_litestream_lock",
				"_litestream_seq",
			},
		}

		if err := squibble.Validate(ctx, sqlConn, dbSchema, &opts); err != nil {
			return nil, fmt.Errorf("validating schema: %w", err)
		}
	}

	db := HSDatabase{
		DB:       dbConn,
		cfg:      cfg,
		regCache: regCache,
	}

	return &db, err
}

func openDB(cfg types.DatabaseConfig) (*gorm.DB, error) {
	// TODO(kradalby): Integrate this with zerolog
	var dbLogger logger.Interface
	if cfg.Debug {
		dbLogger = util.NewDBLogWrapper(&log.Logger, cfg.Gorm.SlowThreshold, cfg.Gorm.SkipErrRecordNotFound, cfg.Gorm.ParameterizedQueries)
	} else {
		dbLogger = logger.Default.LogMode(logger.Silent)
	}

	switch cfg.Type {
	case types.DatabaseSqlite:
		dir := filepath.Dir(cfg.Sqlite.Path)
		err := util.EnsureDir(dir)
		if err != nil {
			return nil, fmt.Errorf("creating directory for sqlite: %w", err)
		}

		log.Info().
			Str("database", types.DatabaseSqlite).
			Str("path", cfg.Sqlite.Path).
			Msg("Opening database")

		// Build SQLite configuration with pragmas set at connection time
		sqliteConfig := sqliteconfig.Default(cfg.Sqlite.Path)
		if cfg.Sqlite.WriteAheadLog {
			sqliteConfig.JournalMode = sqliteconfig.JournalModeWAL
			sqliteConfig.WALAutocheckpoint = cfg.Sqlite.WALAutoCheckPoint
		}

		connectionURL, err := sqliteConfig.ToURL()
		if err != nil {
			return nil, fmt.Errorf("building sqlite connection URL: %w", err)
		}

		db, err := gorm.Open(
			sqlite.Open(connectionURL),
			&gorm.Config{
				PrepareStmt: cfg.Gorm.PrepareStmt,
				Logger:      dbLogger,
			},
		)

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we can't use the gorm
		// connection pool as of 2022/02/23.
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetConnMaxIdleTime(time.Hour)

		return db, err

	case types.DatabasePostgres:
		dbString := fmt.Sprintf(
			"host=%s dbname=%s user=%s",
			cfg.Postgres.Host,
			cfg.Postgres.Name,
			cfg.Postgres.User,
		)

		log.Info().
			Str("database", types.DatabasePostgres).
			Str("path", dbString).
			Msg("Opening database")

		if sslEnabled, err := strconv.ParseBool(cfg.Postgres.Ssl); err == nil {
			if !sslEnabled {
				dbString += " sslmode=disable"
			}
		} else {
			dbString += " sslmode=" + cfg.Postgres.Ssl
		}

		if cfg.Postgres.Port != 0 {
			dbString += fmt.Sprintf(" port=%d", cfg.Postgres.Port)
		}

		if cfg.Postgres.Pass != "" {
			dbString += " password=" + cfg.Postgres.Pass
		}

		db, err := gorm.Open(postgres.Open(dbString), &gorm.Config{
			Logger: dbLogger,
		})
		if err != nil {
			return nil, err
		}

		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(cfg.Postgres.MaxIdleConnections)
		sqlDB.SetMaxOpenConns(cfg.Postgres.MaxOpenConnections)
		sqlDB.SetConnMaxIdleTime(
			time.Duration(cfg.Postgres.ConnMaxIdleTimeSecs) * time.Second,
		)

		return db, nil
	}

	return nil, fmt.Errorf(
		"database of type %s is not supported: %w",
		cfg.Type,
		errDatabaseNotSupported,
	)
}

func runMigrations(cfg types.DatabaseConfig, dbConn *gorm.DB, migrations *gormigrate.Gormigrate) error {
	if cfg.Type == types.DatabaseSqlite {
		// SQLite: Run migrations step-by-step, only disabling foreign keys when necessary

		// List of migration IDs that require foreign keys to be disabled
		// These are migrations that perform complex schema changes that GORM cannot handle safely with FK enabled
		// NO NEW MIGRATIONS SHOULD BE ADDED HERE. ALL NEW MIGRATIONS MUST RUN WITH FOREIGN KEYS ENABLED.
		migrationsRequiringFKDisabled := map[string]bool{
			"202501221827": true, // Route table automigration with FK constraint issues
			"202501311657": true, // PreAuthKey table automigration with FK constraint issues
			// Add other migration IDs here as they are identified to need FK disabled
		}

		// Get the current foreign key status
		var fkOriginallyEnabled int
		if err := dbConn.Raw("PRAGMA foreign_keys").Scan(&fkOriginallyEnabled).Error; err != nil {
			return fmt.Errorf("checking foreign key status: %w", err)
		}

		// Get all migration IDs in order from the actual migration definitions
		// Only IDs that are in the migrationsRequiringFKDisabled map will be processed with FK disabled
		// any other new migrations are ran after.
		migrationIDs := []string{
			// v0.25.0
			"202501221827",
			"202501311657",
			"202502070949",

			// v0.26.0
			"202502131714",
			"202502171819",
			"202505091439",
			"202505141324",

			// As of 2025-07-02, no new IDs should be added here.
			// They will be ran by the migrations.Migrate() call below.
		}

		for _, migrationID := range migrationIDs {
			log.Trace().Caller().Str("migration_id", migrationID).Msg("Running migration")
			needsFKDisabled := migrationsRequiringFKDisabled[migrationID]

			if needsFKDisabled {
				// Disable foreign keys for this migration
				if err := dbConn.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
					return fmt.Errorf("disabling foreign keys for migration %s: %w", migrationID, err)
				}
			} else {
				// Ensure foreign keys are enabled for this migration
				if err := dbConn.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
					return fmt.Errorf("enabling foreign keys for migration %s: %w", migrationID, err)
				}
			}

			// Run up to this specific migration (will only run the next pending migration)
			if err := migrations.MigrateTo(migrationID); err != nil {
				return fmt.Errorf("running migration %s: %w", migrationID, err)
			}
		}

		if err := dbConn.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return fmt.Errorf("restoring foreign keys: %w", err)
		}

		// Run the rest of the migrations
		if err := migrations.Migrate(); err != nil {
			return err
		}

		// Check for constraint violations at the end
		type constraintViolation struct {
			Table           string
			RowID           int
			Parent          string
			ConstraintIndex int
		}

		var violatedConstraints []constraintViolation

		rows, err := dbConn.Raw("PRAGMA foreign_key_check").Rows()
		if err != nil {
			return err
		}

		for rows.Next() {
			var violation constraintViolation
			if err := rows.Scan(&violation.Table, &violation.RowID, &violation.Parent, &violation.ConstraintIndex); err != nil {
				return err
			}

			violatedConstraints = append(violatedConstraints, violation)
		}
		_ = rows.Close()

		if len(violatedConstraints) > 0 {
			for _, violation := range violatedConstraints {
				log.Error().
					Str("table", violation.Table).
					Int("row_id", violation.RowID).
					Str("parent", violation.Parent).
					Msg("Foreign key constraint violated")
			}

			return errForeignKeyConstraintsViolated
		}
	} else {
		// PostgreSQL can run all migrations in one block - no foreign key issues
		if err := migrations.Migrate(); err != nil {
			return err
		}
	}

	return nil
}

func (hsdb *HSDatabase) PingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sqlDB, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

func (hsdb *HSDatabase) Close() error {
	db, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	if hsdb.cfg.Database.Type == types.DatabaseSqlite && hsdb.cfg.Database.Sqlite.WriteAheadLog {
		db.Exec("VACUUM")
	}

	return db.Close()
}

func (hsdb *HSDatabase) Read(fn func(rx *gorm.DB) error) error {
	rx := hsdb.DB.Begin()
	defer rx.Rollback()
	return fn(rx)
}

func Read[T any](db *gorm.DB, fn func(rx *gorm.DB) (T, error)) (T, error) {
	rx := db.Begin()
	defer rx.Rollback()
	ret, err := fn(rx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, nil
}

func (hsdb *HSDatabase) Write(fn func(tx *gorm.DB) error) error {
	tx := hsdb.DB.Begin()
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit().Error
}

func Write[T any](db *gorm.DB, fn func(tx *gorm.DB) (T, error)) (T, error) {
	tx := db.Begin()
	defer tx.Rollback()
	ret, err := fn(tx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, tx.Commit().Error
}

// __BEGIN_CYLONIX_MOD__
func Sort(db *gorm.DB, sortBy, sortDesc string) *gorm.DB {
	if sortBy == "" {
		return db
	}
	by := strings.Split(sortBy, ",")
	desc := []string{}
	if sortDesc != "" {
		desc = strings.Split(sortDesc, ",")
	}
	for i := range by {
		orderStr := by[i]
		if len(desc) > i {
			switch desc[i] {
			case "desc":
				orderStr += " desc"
			case "asc":
				orderStr += " asc"
			}
		}
		db = db.Order(orderStr)
	}
	return db
}
func Page(db *gorm.DB, total int64, page, pageSize int) *gorm.DB {
	if page > 0 && pageSize > 0 {
		limit := int(total) - (page-1)*pageSize
		if limit < 0 {
			limit = 0
		}
		if limit > pageSize {
			limit = pageSize
		}
		return db.Limit(limit).Offset((page - 1) * pageSize)
	}
	return db
}

func Filter(rx *gorm.DB, keyMap map[string]string, filterBy, filterValue, tableName string) *gorm.DB {
	if filterBy == "" || filterValue == "" {
		return rx
	}
	filters := strings.Split(filterBy, ",")
	values := strings.Split(filterValue, ",")
	if len(filters) != len(values) {
		return rx
	}
	for i := range filters {
		like := "%" + values[i] + "%"
		if filters[i] == "username" {
			if tableName == "users" {
				rx = rx.Where("name like ? OR login_name like ?", like, like)
			} else {
				rx = rx.Joins("JOIN users ON users.id = " + tableName + ".user_id")
				rx = rx.Where("users.name like ? OR users.login_name like ?", like, like)
			}
		} else {
			if dbField, ok := keyMap[filters[i]]; ok {
				rx = rx.Where(dbField+" like ?", like)
			} else {
				rx = rx.Where(filters[i]+" like ?", like)
			}
		}
	}
	return rx
}

func ListWithOptions[T any](model T, rx *gorm.DB,
	listFunc func(*gorm.DB) ([]T, error),
	idList []uint64, namespace *string, networkField, network, username string,
	onlineOnly bool, namespaceLike bool, tableName string, onlineIDs []uint64,
	filterByKeyMap map[string]string,
	filterBy, filterValue, sortBy, sortDesc string, page, pageSize int,
) ([]T, int64, error) {
	var m interface{}
	m = model
	v := reflect.ValueOf(model)
	if v.Kind() == reflect.Struct {
		m = &model
	}

	var total int64

	if username != "" {
		user := &types.User{}
		err := rx.Model(&types.User{}).First(user, "name = ?", username).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, 0, nil
			}
			return nil, 0, err
		}
		rx = rx.Model(m)
		rx = rx.Where("user_id = ?", user.ID)
	} else {
		rx = rx.Model(m)
	}

	if networkField != "" && network != "" {
		rx = rx.Where(tableName+"."+networkField+" = ?", network)
	}

	if namespace != nil {
		if namespaceLike {
			rx = rx.Where(tableName+".namespace LIKE ?", "%"+*namespace+"%")
		} else {
			rx = rx.Where(tableName+".namespace = ?", *namespace)
		}
	}
	if len(idList) > 0 {
		rx = rx.Where(tableName+".id in ?", idList)
	}
	if onlineOnly {
		log.Debug().Interface("onlineIDs", onlineIDs).Msg("online IDs filter applied")
		rx = rx.Where(tableName+".last_seen IS NULL OR "+tableName+".id in ?", onlineIDs)
	}
	rx = Filter(rx, filterByKeyMap, filterBy, filterValue, tableName)
	if err := rx.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	rx = Sort(rx, sortBy, sortDesc)
	rx = Page(rx, total, int(page), int(pageSize))
	ret, err := listFunc(rx)

	return ret, total, err
}

// __END_CYLONIX_MOD__
