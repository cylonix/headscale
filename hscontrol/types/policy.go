package types

import (
	"errors"

	"gorm.io/gorm"
)

var (
	ErrPolicyNotFound         = errors.New("acl policy not found")
	ErrPolicyUpdateIsDisabled = errors.New("update is disabled for modes other than 'database'")
)

// Policy represents a policy in the database.
type Policy struct {
	gorm.Model

	UserID    *uint  // __CYLINIX_MOD__
	User      *User  // __CYLINIX_MOD__
	Namespace string // __CYLONIX_MOD__

	// Data contains the policy in HuJSON format.
	Data string
}
