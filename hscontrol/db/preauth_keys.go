package db

import (
	"crypto/rand"
	"encoding/hex"
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
	keyStr, ipv4, ipv6 string, // __CYLONIX_MOD__
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKey, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKey, error) {
		return CreatePreAuthKey(tx, userName, reusable, ephemeral, keyStr, ipv4, ipv6, expiration, aclTags) // __CYLONIX_MOD__
	})
}

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
func CreatePreAuthKey(
	tx *gorm.DB,
	userName string,
	reusable bool,
	ephemeral bool,
	keyStr, ipv4, ipv6 string, // __CYLONIX_MOD__
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
	kstr, err := generateKey()
	if err != nil {
		return nil, err
	}
	// __BEGIN_CYLONIX_MOD__
	if keyStr != "" {
		kstr = keyStr
	}
	// __END_CYLONIX_MOD__
	key := types.PreAuthKey{
		Key:        kstr,
		UserID:     user.ID,
		User:       *user,
		Reusable:   reusable,
		Ephemeral:  ephemeral,
		CreatedAt:  &now,
		Expiration: expiration,
		Namespace:  user.GetNamespace(), // __CYLONIX_MOD__
		IPv4:       ipv4, // __CYLONIX_MOD__
		IPv6:       ipv6, // __CYLONIX_MDO__
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
	idList []uint64, namespace *string, username string,
	filterBy, filterValue, sortBy string, sortDesc bool,
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
			idList, namespace, username,
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

func (hsdb *HSDatabase) ExpirePreAuthKey(k *types.PreAuthKey) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return ExpirePreAuthKey(tx, k)
	})
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func ExpirePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	if err := tx.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
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

func generateKey() (string, error) {
	size := 24
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
