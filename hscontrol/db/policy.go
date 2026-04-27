package db

import (
	"errors"
	"os"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SetPolicy sets the policy in the database.
func (hsdb *HSDatabase) SetPolicy(policy, namespace, network string) (*types.Policy, error) { // __CYLONIX_MOD__
	// Create a new policy.
	p := types.Policy{
		Data:      policy,
		Network:   network,   // __CYLONIX_MOD__
		Namespace: namespace, // __CYLONIX_MOD__
	}

	if err := hsdb.DB.Clauses(clause.Returning{}).Create(&p).Error; err != nil {
		return nil, err
	}

	return &p, nil
}

// GetPolicy returns the latest policy in the database, optionally scoped to a
// cylonix namespace and network.
func (hsdb *HSDatabase) GetPolicy(namespace, network *string) (*types.Policy, error) { // __CYLONIX_MOD__
	var p types.Policy

	// __BEGIN_CYLONIX_ADD__
	db := hsdb.DB
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if network != nil {
		db = db.Where("network = ?", *network)
	}
	// __END_CYLONIX_ADD__

	// Query:
	// SELECT * FROM policies ORDER BY id DESC LIMIT 1;
	if err := db. // __CYLONIX_MOD__
			Order("id DESC").
			Limit(1).
			First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.ErrPolicyNotFound
		}

		return nil, err
	}

	return &p, nil
}

// GetPolicy returns the latest policy from the database.
// This standalone function can be used in contexts where HSDatabase is not
// available, such as during migrations.
func GetPolicy(tx *gorm.DB) (*types.Policy, error) {
	var p types.Policy

	err := tx.
		Order("id DESC").
		Limit(1).
		First(&p).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.ErrPolicyNotFound
		}

		return nil, err
	}

	return &p, nil
}

// __BEGIN_CYLONIX_ADD__
// ListLatestPolicyPerTailnet returns the latest policy row for each
// distinct (namespace, network) pair in the policies table. SetPolicy
// inserts (never updates), so the schema accumulates one row per
// edit; the "latest per pair" projection is what callers actually want.
//
// Used by the multi-tenant ReloadPolicy path to repopulate
// PolicyManager.tailnetPolicies after process startup.
//
// Rows with empty (namespace, network) — i.e. legacy unscoped writes —
// are excluded; callers retrieve the global policy via GetPolicy.
func (hsdb *HSDatabase) ListLatestPolicyPerTailnet() ([]types.Policy, error) {
	return ListLatestPolicyPerTailnet(hsdb.DB)
}

// ListLatestPolicyPerTailnet is the standalone variant for contexts
// where HSDatabase is not available (migrations, ReloadPolicy via the
// already-open *gorm.DB).
func ListLatestPolicyPerTailnet(tx *gorm.DB) ([]types.Policy, error) {
	// Subquery: max(id) per (namespace, network), excluding the
	// unscoped pair (the global policy).
	var rows []types.Policy
	sub := tx.
		Model(&types.Policy{}).
		Select("max(id) as id").
		Where("namespace <> ? AND network <> ?", "", "").
		Group("namespace, network")

	err := tx.
		Model(&types.Policy{}).
		Where("id IN (?)", sub).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// __END_CYLONIX_ADD__

// PolicyBytes loads policy configuration from file or database based on the configured mode.
// Returns nil if no policy is configured, which is valid.
// This standalone function can be used in contexts where HSDatabase is not available,
// such as during migrations.
func PolicyBytes(tx *gorm.DB, cfg *types.Config) ([]byte, error) {
	switch cfg.Policy.Mode {
	case types.PolicyModeFile:
		path := cfg.Policy.Path

		// It is fine to start headscale without a policy file.
		if len(path) == 0 {
			return nil, nil
		}

		absPath := util.AbsolutePathFromConfigPath(path)

		return os.ReadFile(absPath)

	case types.PolicyModeDB:
		p, err := GetPolicy(tx)
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				return nil, nil
			}

			return nil, err
		}

		if p.Data == "" {
			return nil, nil
		}

		return []byte(p.Data), nil
	}

	return nil, nil
}
