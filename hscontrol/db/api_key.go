package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	apiPrefixLength = 7
	apiKeyLength    = 32
)

var ErrAPIKeyFailedToParse = errors.New("failed to parse ApiKey")

// CreateAPIKey creates a new ApiKey in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
	username string,  // __CYLONIX_MOD__
	namespace string, // __CYLONIX_MOD__
	scopeType string, // __CYLONIX_MOD__
	scopeValue string, // __CYLONIX_MOD__
) (string, *types.APIKey, error) {
	prefix, err := util.GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", nil, err
	}

	toBeHashed, err := util.GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", nil, err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := prefix + "." + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	// __BEGIN_CYLONIX_MOD__
	var userID *uint
	if username != "" {
		user, err := hsdb.GetUser(username)
		if err != nil {
			return "", nil, err
		}
		userID = &user.ID
	}
	// __END_CYLONIX_MOD__

	key := types.APIKey{
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
		UserID:     userID,                         // __CYLONIX_MOD__
		Namespace:  namespace,                      // __CYLONIX_MOD__
		ScopeType:  types.AuthScopeType(scopeType), // __CYLONIX_MOD__
		ScopeValue: scopeValue,                     // __CYLONIX_MOD__
	}

	if err := hsdb.DB.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	keys := []types.APIKey{}
	if err := hsdb.DB.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	key := types.APIKey{}
	if result := hsdb.DB.Preload("User").First(&key, "prefix = ?", prefix); result.Error != nil { // __CYLONIX_MOD__
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	key := types.APIKey{}
	if result := hsdb.DB.Find(&types.APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	if result := hsdb.DB.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	if err := hsdb.DB.Model(&key).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

// __BEGIN_CYLONIX_MOD__
func (hsdb *HSDatabase) RefreshAPIKey(id uint64, expire time.Time) error {
	return hsdb.DB.
		Model(&types.APIKey{ID: id}).
		Update("Expiration", expire).
		Error
}
func (hsdb *HSDatabase) ValidateAPIKey(keyStr string) (bool, error) {
	_, valid, err := hsdb.GetAndValidateAPIKey(keyStr)
	return valid, err
}

func (hsdb *HSDatabase) GetAndValidateAPIKey(keyStr string) (*types.APIKey, bool, error) {
	prefix, hash, found := strings.Cut(keyStr, ".")
	if !found {
		return nil, false, nil
	}

	key, err := hsdb.GetAPIKey(prefix)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to validate api key: %w", err)
	}

	if key.Expiration.Before(time.Now()) {
		return nil, false, nil
	}

	if err := bcrypt.CompareHashAndPassword(key.Hash, []byte(hash)); err != nil {
		return nil, false, nil
	}

	return key, true, nil
}
func (hsdb *HSDatabase) ListAPIKeysWithOptions(
	idList []uint64, namespace *string, network, username string,
	filterBy, filterValue, sortBy string, sortDesc bool,
	page, pageSize int,
) (int, []*types.APIKey, error) {
	var total int64
	keys, err := Read(hsdb.DB, func(rx *gorm.DB) ([]*types.APIKey, error) {
		keys, count, err := ListWithOptions(
			&types.APIKey{}, rx, 
			func(rx *gorm.DB) ([]*types.APIKey, error) {
				var keys []*types.APIKey
				err := rx.Preload("User").Find(&keys).Error
				return keys, err
			},
			idList, namespace, "network", network, username,
			filterBy, filterValue, sortBy, sortDesc, page, pageSize,
		)
		total = count
		return keys, err
	})
	return int(total), keys, err
}

func DeleteAPIKeysByUser(tx *gorm.DB, userID uint) error {
	return tx.Delete(&types.APIKey{}, "user_id = ?", userID).Error
}
// __END_CYLONIX_MOD__
