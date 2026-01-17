package db

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/types/ptr"
)

var (
	ErrPreAuthKeyNotFound          = errors.New("AuthKey not found")
	ErrPreAuthKeyExpired           = errors.New("AuthKey expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("AuthKey has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("AuthKey tag is invalid")
)

func (hsdb *HSDatabase) CreatePreAuthKey(
	userName string,
	reusable bool,
	ephemeral bool,
	description, ipv4, ipv6 string, // __CYLONIX_MOD__
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKey, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKey, error) {
		return CreatePreAuthKey(tx, userName, reusable, ephemeral, description, ipv4, ipv6, expiration, aclTags) // __CYLONIX_MOD__
	})
}

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
func CreatePreAuthKey(
	tx *gorm.DB,
	userName string,
	reusable bool,
	ephemeral bool,
	description, ipv4, ipv6 string, // __CYLONIX_MOD__
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKey, error) {
	user, err := GetUser(tx, userName)
	if err != nil {
		return nil, err
	}

	for _, tag := range aclTags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf(
				"%w: '%s' did not begin with 'tag:'",
				ErrPreAuthKeyACLTagInvalid,
				tag,
			)
		}
	}

	now := time.Now().UTC()
	kstr, err := generatePreAuthKey()
	if err != nil {
		return nil, err
	}
	key := types.PreAuthKey{
		Key:         kstr,
		UserID:      user.ID,
		User:        *user,
		Reusable:    reusable,
		Ephemeral:   ephemeral,
		CreatedAt:   &now,
		Expiration:  expiration,
		Namespace:   user.GetNamespace(), // __CYLONIX_MOD__
		IPv4:        ipv4,                // __CYLONIX_MOD__
		IPv6:        ipv6,                // __CYLONIX_MDO__
		Description: description,         // __CYLONIX_MOD__
	}

	if err := tx.Save(&key).Error; err != nil {
		return nil, fmt.Errorf("failed to create key in the database: %w", err)
	}

	if len(aclTags) > 0 {
		seenTags := map[string]bool{}

		for _, tag := range aclTags {
			if !seenTags[tag] {
				if err := tx.Save(&types.PreAuthKeyACLTag{PreAuthKeyID: key.ID, Tag: tag}).Error; err != nil {
					return nil, fmt.Errorf(
						"failed to create key tag in the database: %w",
						err,
					)
				}
				seenTags[tag] = true
			}
		}
	}

	return &key, nil
}

func (hsdb *HSDatabase) ListPreAuthKeys(userName string) ([]types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]types.PreAuthKey, error) {
		return ListPreAuthKeys(rx, userName)
	})
}

// __BEGIN_CYLONIX_MOD__
func (hsdb *HSDatabase) ListPreAuthKeysWithOptions(
	idList []uint64, namespace *string, namespaceLike bool,
	network, username string,
	filterBy, filterValue, sortBy, sortDesc string,
	page, pageSize int,
) (int, []*types.PreAuthKey, error) {
	var total int64
	keys, err := Read(hsdb.DB, func(rx *gorm.DB) ([]*types.PreAuthKey, error) {
		keys, count, err := ListWithOptions(
			&types.PreAuthKey{}, rx,
			func(rx *gorm.DB) ([]*types.PreAuthKey, error) {
				keys := []*types.PreAuthKey{}
				rx = rx.Preload("User").Preload("ACLTags")
				if err := rx.Find(&keys).Error; err != nil {
					return nil, err
				}
				return keys, nil
			},
			idList, namespace, "network", network, username,
			false, namespaceLike,
			"pre_auth_keys", nil, nil,
			filterBy, filterValue, sortBy, sortDesc, page, pageSize,
		)
		total = count
		return keys, err

	})
	return int(total), keys, err
}
func UnauthorizedPreAuthKeyError(err error) bool {
	return errors.Is(err, ErrSingleUseAuthKeyHasBeenUsed) ||
		errors.Is(err, ErrPreAuthKeyNotFound) ||
		errors.Is(err, ErrPreAuthKeyExpired)
}

func (hsdb *HSDatabase) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.PreAuthKey, error) {
		return GetPreAuthKeyByID(rx, id)
	})
}

func GetPreAuthKeyByID(tx *gorm.DB, id uint64) (*types.PreAuthKey, error) {
	pak := types.PreAuthKey{}
	err := tx.Preload("User").Preload("ACLTags").First(&pak, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPreAuthKeyNotFound
		}
		return nil, err
	}
	return &pak, err
}

func (hsdb *HSDatabase) DeletePreAuthKey(key types.PreAuthKey) error {
	if result := hsdb.DB.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}
// __END_CYLONIX_MOD__

// ListPreAuthKeys returns the list of PreAuthKeys for a user.
func ListPreAuthKeys(tx *gorm.DB, userName string) ([]types.PreAuthKey, error) {
	user, err := GetUser(tx, userName)
	if err != nil {
		return nil, err
	}

	keys := []types.PreAuthKey{}
	if err := tx.Preload("User").Preload("ACLTags").Where(&types.PreAuthKey{UserID: user.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key.
func GetPreAuthKey(tx *gorm.DB, user string, key string) (*types.PreAuthKey, error) {
	pak, err := ValidatePreAuthKey(tx, key)
	if err != nil {
		return nil, err
	}

	if pak.User.Name != user {
		return nil, ErrUserMismatch
	}

	return pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist.
func DestroyPreAuthKey(tx *gorm.DB, pak types.PreAuthKey) error {
	return tx.Transaction(func(db *gorm.DB) error {
		if result := db.Unscoped().Where(types.PreAuthKeyACLTag{PreAuthKeyID: pak.ID}).Delete(&types.PreAuthKeyACLTag{}); result.Error != nil {
			return result.Error
		}

		if result := db.Unscoped().Delete(pak); result.Error != nil {
			return result.Error
		}

		return nil
	})
}

func (hsdb *HSDatabase) ExpirePreAuthKey(k *types.PreAuthKey, expiry time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return ExpirePreAuthKey(tx, k, expiry)
	})
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func ExpirePreAuthKey(tx *gorm.DB, k *types.PreAuthKey, expiry time.Time) error {
	if err := tx.Model(&k).Update("Expiration", expiry).Error; err != nil {
		return err
	}

	return nil
}

// UsePreAuthKey marks a PreAuthKey as used.
func UsePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	k.Used = true
	if err := tx.Save(k).Error; err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) ValidatePreAuthKey(k string) (*types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.PreAuthKey, error) {
		return ValidatePreAuthKey(rx, k)
	})
}

// ValidatePreAuthKey does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used.
func ValidatePreAuthKey(tx *gorm.DB, k string) (*types.PreAuthKey, error) {
	pak := types.PreAuthKey{}
	if result := tx.Preload("User").Preload("ACLTags").First(&pak, "key = ?", k); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, ErrPreAuthKeyExpired
	}

	if pak.Reusable { // we don't need to check if has been used before
		return &pak, nil
	}

	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Where(&types.Node{AuthKeyID: ptr.To(pak.ID)}).
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	if len(nodes) != 0 || pak.Used {
		return nil, ErrSingleUseAuthKeyHasBeenUsed
	}

	return &pak, nil
}

// __BEGIN_CYLONIX_MOD__
// Generate 32 bytes (256 bits) of random data
// Use URL-safe base64 encoding with a prefix
func generateRandomKey(size int) (string, error) {
    bytes := make([]byte, size)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %w", err)
    }
    return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func generatePreAuthKey() (string, error) {
    // Generate main key (24 bytes)
    main, err := generateRandomKey(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate main key: %w", err)
	}

    // Generate short prefix
    prefix, err := generateRandomKey(8)
	if err != nil {
		return "", fmt.Errorf("failed to generate prefix: %w", err)
	}

    // Combine into final format: cy-auth-{prefix}-{main}
    return fmt.Sprintf("cy-auth-%s-%s", prefix, main), nil
}

// Helper function to get displayable version of key
func GetPreAuthKeyDisplayKey(key string) string {
    if len(key) > 20 {
		return key[:20] + "..." // Shorten to first 22 characters
	}
	return key // Return as is if already short enough
}

// __END_CYLONIX_MOD__
