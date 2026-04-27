-- This file is the representation of the SQLite schema of Headscale.
-- It is the "source of truth" and is used to validate any migrations
-- that are run against the database to ensure it ends in the expected state.

CREATE TABLE migrations(id text,PRIMARY KEY(id));

CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,

  -- __BEGIN_CYLONIX_ADD__
  -- Cylonix multi-tenant fields. login_name is the human-readable login for a
  -- tenant user; namespace is the tenant id; network is the tenant's active
  -- network_domain. The composite unique `users_namespace_login` enforces that
  -- a given login_name is unique within a namespace but allowed to repeat
  -- across namespaces.
  login_name text,
  namespace text,
  network text,
  -- __END_CYLONIX_ADD__

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);


-- The following three UNIQUE indexes work together to enforce the user identity model:
--
-- 1. Users can be either local (provider_identifier is NULL) or from external providers (provider_identifier set)
-- 2. Each external provider identifier must be unique across the system
-- 3. Local usernames must be unique among local users
-- 4. The same username can exist across different providers with different identifiers
--
-- Examples:
-- - Can create local user "alice" (provider_identifier=NULL)
-- - Can create external user "alice" with GitHub (name="alice", provider_identifier="alice_github")
-- - Can create external user "alice" with Google (name="alice", provider_identifier="alice_google")
-- - Cannot create another local user "alice" (blocked by idx_name_no_provider_identifier)
-- - Cannot create another user with provider_identifier="alice_github" (blocked by idx_provider_identifier)
-- - Cannot create user "bob" with provider_identifier="alice_github" (blocked by idx_name_provider_identifier)
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
-- __BEGIN_CYLONIX_ADD__
-- Composite unique so the same login_name can repeat across namespaces.
-- GORM emits this with login_name first because LoginName is declared before
-- Namespace in the User struct. The cylonix "Name string gorm:\"unique\""
-- creates a column-level UNIQUE constraint (not a named INDEX), so we don't
-- declare it here. Format matches GORM's emitted DDL (backticks, no space).
CREATE UNIQUE INDEX `users_namespace_login` ON `users`(`login_name`,`namespace`);
-- __END_CYLONIX_ADD__

CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  prefix text,
  hash blob,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,

  -- __BEGIN_CYLONIX_ADD__
  namespace text,
  ipv4 text,
  ipv6 text,
  description text,
  -- __END_CYLONIX_ADD__

  created_at datetime,

  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,

  -- __BEGIN_CYLONIX_ADD__
  -- Cylonix auth-scope metadata for per-tenant API keys.
  scope_type text,
  scope_value text,
  user_id integer,
  network text,
  namespace text,
  -- __END_CYLONIX_ADD__

  created_at datetime

  -- __BEGIN_CYLONIX_ADD__
  , CONSTRAINT fk_api_keys_user FOREIGN KEY(user_id) REFERENCES users(id)
  -- __END_CYLONIX_ADD__
);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);

CREATE TABLE nodes(
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
  tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,

  -- __BEGIN_CYLONIX_ADD__
  -- Cylonix per-node extras. NetworkDomain participates in the compound
  -- unique index `nodes_network_domain_given_name` so two cylonix
  -- network_domains can have nodes with overlapping DNS names without
  -- colliding. IsJailed is runtime-only (gorm:"-") so no column.
  is_wireguard_only numeric,
  stable_id text,
  namespace text,
  network_domain text,
  cap_version integer,
  health text,
  -- __END_CYLONIX_ADD__

  created_at datetime,
  updated_at datetime,
  deleted_at datetime,

  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);
-- __BEGIN_CYLONIX_ADD__
-- Cylonix compound unique indexes. GORM uses the field declaration order in
-- the struct; we replicate that here so squibble validation passes. The
-- explicit backticks + no-space format matches GORM's emitted DDL byte-for-
-- byte (squibble compares sqlite_master.sql verbatim).
-- - nodes_user_machine_key: the same physical device may be registered across
--   different cylonix tenants (users), so machine_key is unique *per user*.
-- - nodes_network_domain_given_name: GivenName is unique per network_domain,
--   not globally. PARTIAL (WHERE given_name != '') so empty fixture rows and
--   mid-insert transient states don't collide.
CREATE UNIQUE INDEX `nodes_user_machine_key` ON `nodes`(`machine_key`,`user_id`);
CREATE UNIQUE INDEX "nodes_network_domain_given_name" ON nodes(given_name, network_domain) WHERE given_name != '';
-- __END_CYLONIX_ADD__

-- __BEGIN_CYLONIX_ADD__
CREATE TABLE capabilities(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  namespace text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX `idx_capabilities_deleted_at` ON `capabilities`(`deleted_at`);
CREATE UNIQUE INDEX `capabilities_name_namespace` ON `capabilities`(`name`,`namespace`);

-- many2many relation tables for node <-> capabilities / users.
CREATE TABLE node_capabilities_relation(
  node_id integer,
  capability_id integer,
  PRIMARY KEY(node_id, capability_id),
  CONSTRAINT fk_node_capabilities_relation_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
  CONSTRAINT fk_node_capabilities_relation_capability FOREIGN KEY(capability_id) REFERENCES capabilities(id) ON DELETE CASCADE
);

CREATE TABLE node_would_share_to_users_relation(
  node_id integer,
  user_id integer,
  PRIMARY KEY(node_id, user_id),
  CONSTRAINT fk_node_would_share_to_users_relation_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
  CONSTRAINT fk_node_would_share_to_users_relation_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE node_accepted_share_to_users_relation(
  node_id integer,
  user_id integer,
  PRIMARY KEY(node_id, user_id),
  CONSTRAINT fk_node_accepted_share_to_users_relation_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
  CONSTRAINT fk_node_accepted_share_to_users_relation_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- __END_CYLONIX_ADD__

CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,

  -- __BEGIN_CYLONIX_ADD__
  -- Multi-tenant scoping for policies. user_id allows per-user policy
  -- overrides under a tenant.
  user_id integer,
  namespace text,
  network text,
  -- __END_CYLONIX_ADD__

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);

-- __BEGIN_CYLONIX_ADD__
-- NOTE: the `routes` table was renamed to `routes_archive` by the v0.26
-- migration only on databases that already had a `routes` table from an
-- earlier cylonix deployment. Fresh installs do not create it. We therefore
-- do not declare it in this canonical schema — squibble will allow extra
-- tables in the live DB on migrated installs without complaining.
-- __END_CYLONIX_ADD__
