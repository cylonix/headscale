package db

import (
	"errors"

	"github.com/juanfont/headscale/hscontrol/types"
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

// GetPolicy returns the latest policy in the database.
func (hsdb *HSDatabase) GetPolicy(namespace, network *string) (*types.Policy, error) { // __CYLONIX_MOD__
	var p types.Policy

	// __ BEGIN_CYLONIX_MOD __
	db := hsdb.DB
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if network != nil {
		db = db.Where("network = ?", *network)
	}
	// __ END_CYLONIX_MOD __

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
