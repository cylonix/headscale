// __BEGIN_CYLONIX_MOD__
// Cylonix extensions to upstream's preauth_keys.go.
//
// Upstream v0.28 refactored PreAuthKey to use bcrypt-hashed secrets with a
// separate plaintext return struct (PreAuthKeyNew). CreatePreAuthKey takes
// a *types.UserID (may be nil for system-created tagged keys), reusable,
// ephemeral, expiration, and aclTags — nothing else.
//
// Cylonix needs additional per-key state for its multi-tenant deployment:
//   - Namespace: cylonix tenant scope
//   - IPv4/IPv6: pre-allocated addresses reserved for this key
//   - Description: operator-visible annotation
//
// This file layers that state onto upstream's API without modifying
// preauth_keys.go. Callers in cylonix-manager use CreatePreAuthKeyExt instead
// of CreatePreAuthKey.

package db

import (
	"errors"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// UnauthorizedPreAuthKeyError returns true if err represents a PreAuthKey
// state that should be mapped to an "unauthorized" HTTP/gRPC status.
func UnauthorizedPreAuthKeyError(err error) bool {
	return errors.Is(err, ErrSingleUseAuthKeyHasBeenUsed) ||
		errors.Is(err, ErrPreAuthKeyNotFound) ||
		errors.Is(err, ErrPreAuthKeyExpired)
}

// CreatePreAuthKeyExtParams bundles cylonix-specific fields so additions
// don't break the function signature each time.
type CreatePreAuthKeyExtParams struct {
	Namespace   string
	IPv4        string
	IPv6        string
	Description string
}

// CreatePreAuthKeyExt wraps upstream's CreatePreAuthKey and then stamps
// cylonix-specific fields onto the resulting row. The returned
// PreAuthKeyNew carries the plaintext key (caller must preserve it — it is
// not retrievable again after creation).
func (hsdb *HSDatabase) CreatePreAuthKeyExt(
	uid *types.UserID,
	reusable, ephemeral bool,
	expiration *time.Time,
	aclTags []string,
	extras CreatePreAuthKeyExtParams,
) (*types.PreAuthKeyNew, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKeyNew, error) {
		pkNew, err := CreatePreAuthKey(tx, uid, reusable, ephemeral, expiration, aclTags)
		if err != nil {
			return nil, err
		}

		if err := tx.Model(&types.PreAuthKey{}).
			Where("id = ?", pkNew.ID).
			Updates(map[string]any{
				"namespace":   extras.Namespace,
				"i_pv_4":      extras.IPv4, // gorm snake_case of IPv4
				"i_pv_6":      extras.IPv6, // gorm snake_case of IPv6
				"description": extras.Description,
			}).Error; err != nil {
			return nil, err
		}

		pkNew.Namespace = extras.Namespace
		pkNew.IPv4 = extras.IPv4
		pkNew.IPv6 = extras.IPv6
		pkNew.Description = extras.Description
		return pkNew, nil
	})
}

// GetPreAuthKeyByID looks up a PreAuthKey by its numeric id.
func (hsdb *HSDatabase) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.PreAuthKey, error) {
		return GetPreAuthKeyByID(rx, id)
	})
}

// GetPreAuthKeyByID is the transaction-scoped form.
func GetPreAuthKeyByID(tx *gorm.DB, id uint64) (*types.PreAuthKey, error) {
	pak := types.PreAuthKey{}
	err := tx.Preload("User").First(&pak, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPreAuthKeyNotFound
		}
		return nil, err
	}
	return &pak, nil
}

// ListPreAuthKeysWithOptionsParams bundles the filter/sort/pagination knobs
// used by cylonix-manager's list endpoint.
type ListPreAuthKeysWithOptionsParams struct {
	IDList        []uint64
	Namespace     *string
	NamespaceLike bool
	Network       string
	Username      string
	FilterBy      string
	FilterValue   string
	SortBy        string
	SortDesc      string
	Page          int
	PageSize      int
}

// ListPreAuthKeysWithOptions returns a paged, optionally-filtered set of
// PreAuthKeys. This is a thin wrapper that defers to the shared
// ListWithOptions helper.
func (hsdb *HSDatabase) ListPreAuthKeysWithOptions(
	p ListPreAuthKeysWithOptionsParams,
) (int, []*types.PreAuthKey, error) {
	var total int64
	keys, err := Read(hsdb.DB, func(rx *gorm.DB) ([]*types.PreAuthKey, error) {
		keys, count, err := ListWithOptions(
			&types.PreAuthKey{}, rx,
			func(rx *gorm.DB) ([]*types.PreAuthKey, error) {
				var ks []*types.PreAuthKey
				if err := rx.Preload("User").Find(&ks).Error; err != nil {
					return nil, err
				}
				return ks, nil
			},
			p.IDList, p.Namespace, "network", p.Network, p.Username,
			false, p.NamespaceLike,
			"pre_auth_keys", nil, nil,
			p.FilterBy, p.FilterValue, p.SortBy, p.SortDesc, p.Page, p.PageSize,
		)
		total = count
		return keys, err
	})
	return int(total), keys, err
}

// __END_CYLONIX_MOD__
