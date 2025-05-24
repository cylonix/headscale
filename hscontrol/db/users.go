package db

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var (
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserStillHasNodes = errors.New("user not empty: node(s) found")
)

func (hsdb *HSDatabase) CreateUser(name string) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, name, nil, nil) // __CYLONIX_MOD__
	})
}

// __BEGIN_CYLONIX_MOD__
func (hsdb *HSDatabase) CreateNamespaceUser(stableID string, namespace, loginName *string) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, stableID, namespace, loginName)
	})
}

func (hsdb *HSDatabase) ListUsersWithOptions(
	idList []uint64, namespace *string, network, username string,
	filterBy, filterValue, sortBy string, sortDesc bool,
	page, pageSize int,
) (int, []*types.User, error) {
	var total int64
	if username != "" {
		log.Debug().Str("username", username).Msg("getting user by username")
		user, err := hsdb.GetUser(username)
		if err != nil {
			return 0, nil, err
		}
		idList = []uint64{uint64(user.ID)}
	}
	ns := "nil"
	if namespace != nil {
		ns = *namespace
	}
	log.Debug().
		Str("namespace", ns).
		Str("network", network).
		Msg("listing users")
	users, err := Read(hsdb.DB, func(rx *gorm.DB) ([]*types.User, error) {
		users, count, err := ListWithOptions(
			&types.User{}, rx, ListUsers,
			idList, namespace, "network", network, "",
			filterBy, filterValue, sortBy, sortDesc, page, pageSize,
		)
		total = count
		return users, err
	})
	return int(total), users, err
}

func (hsdb *HSDatabase) UpdateUserNetworkDomain(
	user, network string,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return UpdateUserNetworkDomain(tx, user, network)
	})
}

func UpdateUserNetworkDomain(tx *gorm.DB, username, network string) error {
	user, err := GetUser(tx, username)
	if err != nil {
		return err
	}
	if user.Network == network {
		return nil
	}
	if network == "" {
		return fmt.Errorf("network domain cannot be empty")
	}
	if user.Network == "" {
		if err := tx.Model(&types.Node{}).
			Where("user_id = ?", user.ID).
			Updates(types.Node{NetworkDomain: network}).Error; err != nil {
			return err
		}
		if err := tx.Model(&types.APIKey{}).
			Where("user_id = ?", user.ID).
			Updates(types.APIKey{Network: network}).Error; err != nil {
			return err
		}
	} else {
		if err := tx.Model(&types.Node{}).
			Where("network_domain = ?", user.Network).
			Updates(types.Node{NetworkDomain: network}).Error; err != nil {
			return err
		}
		if err := tx.Model(&types.Route{}).
			Where("network = ?", user.Network).
			Updates(types.Route{Network: network}).Error; err != nil {
			return err
		}
		if err := tx.Model(&types.Policy{}).
			Where("network = ?", network).
			Updates(types.Policy{Network: network}).Error; err != nil {
			return err
		}
		if err := tx.Model(&types.APIKey{}).
			Where("network = ?", user.Network).
			Updates(types.APIKey{Network: network}).Error; err != nil {
			return err
		}
	}
	if err := tx.Model(&types.User{}).
		Where("name = ?", username).
		Updates(types.User{Network: network}).Error; err != nil {
		return err
	}
	return nil
}

// __END_CYLONIX_MOD__

// CreateUser creates a new User. Returns error if could not be created
// or another user already exists.
func CreateUser(tx *gorm.DB, name string, namespace, loginName *string) (*types.User, error) { // __CYLONIX_MOD__
	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user := types.User{}
	if err := tx.Where("name = ?", name).First(&user).Error; err == nil {
		return nil, ErrUserExists
	}
	user.Name = name
	user.Namespace = namespace // __CYLONIX_MOD__
	user.LoginName = loginName // __CYLONIX_MOD__
	if err := tx.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &user, nil
}

func (hsdb *HSDatabase) DestroyUser(name string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyUser(tx, name)
	})
}

// DestroyUser destroys a User. Returns error if the User does
// not exist or if there are nodes associated with it.
func DestroyUser(tx *gorm.DB, name string) error {
	user, err := GetUser(tx, name)
	if err != nil {
		return ErrUserNotFound
	}

	nodes, err := ListNodesByUser(tx, name)
	if err != nil {
		return err
	}
	if len(nodes) > 0 {
		// __BEGIN_CYLONIX_MOD__
		nodeIDs, _ := types.SliceMap(nodes, func(n *types.Node) (types.NodeID, error){ return n.ID, nil})
		if len(nodeIDs) > 10 {
			nodeIDs = nodeIDs[:10]
		}
		log.Debug().Str("node-ids", fmt.Sprintf("%v", nodeIDs)).Msg("nodes of user")
		// __END_CYLONIX_MOD__
		return ErrUserStillHasNodes
	}

	keys, err := ListPreAuthKeys(tx, name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = DestroyPreAuthKey(tx, key)
		if err != nil {
			return err
		}
	}

	// __BEGIN_CYLONIX_MOD__
	if err := DeleteAPIKeysByUser(tx, user.ID); err != nil {
		return err
	}
	// __END_CYLONIX_MOD__

	if result := tx.Unscoped().Delete(&user); result.Error != nil {
		return result.Error
	}

	return nil
}

func (hsdb *HSDatabase) RenameUser(oldName, newName string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RenameUser(tx, oldName, newName)
	})
}

// RenameUser renames a User. Returns error if the User does
// not exist or if another User exists with the new name.
func RenameUser(tx *gorm.DB, oldName, newName string) error {
	var err error
	oldUser, err := GetUser(tx, oldName)
	if err != nil {
		return err
	}
	err = util.CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = GetUser(tx, newName)
	if err == nil {
		return ErrUserExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return err
	}

	oldUser.Name = newName

	if result := tx.Save(&oldUser); result.Error != nil {
		return result.Error
	}

	return nil
}

func (hsdb *HSDatabase) GetUser(name string) (*types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUser(rx, name)
	})
}

func GetUser(tx *gorm.DB, name string) (*types.User, error) {
	user := types.User{}
	if result := tx.First(&user, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (hsdb *HSDatabase) ListUsers() ([]*types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]*types.User, error) {
		return ListUsers(rx)
	})
}

// ListUsers gets all the existing users.
func ListUsers(tx *gorm.DB) ([]*types.User, error) {
	users := []*types.User{}
	if err := tx.Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}

// ListNodesByUser gets all the nodes in a given user.
func ListNodesByUser(tx *gorm.DB, name string) (types.Nodes, error) {
	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user, err := GetUser(tx, name)
	if err != nil {
		return nil, err
	}

	nodes := types.Nodes{}
	if err := tx.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where(&types.Node{UserID: user.ID}).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) AssignNodeToUser(node *types.Node, username string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return AssignNodeToUser(tx, node, username)
	})
}

// AssignNodeToUser assigns a Node to a user.
func AssignNodeToUser(tx *gorm.DB, node *types.Node, username string) error {
	err := util.CheckForFQDNRules(username)
	if err != nil {
		return err
	}
	user, err := GetUser(tx, username)
	if err != nil {
		return err
	}
	node.User = *user
	if result := tx.Save(&node); result.Error != nil {
		return result.Error
	}

	return nil
}
