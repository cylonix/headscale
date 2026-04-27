package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"

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

func (hsdb *HSDatabase) CreateUser(user types.User) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, user)
	})
}

// __BEGIN_CYLONIX_ADD__
// CreateNamespaceUser builds a types.User with cylonix tenant scoping fields
// (namespace / loginName / networkDomain) and creates it via the upstream
// CreateUser path so tenant uniqueness constraints apply.
func (hsdb *HSDatabase) CreateNamespaceUser(stableID string, namespace, loginName *string, networkDomain string) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, types.User{
			Name:      stableID,
			Namespace: namespace,
			LoginName: loginName,
			Network:   networkDomain,
		})
	})
}

func (hsdb *HSDatabase) ListUsersWithOptions(
	idList []uint64, namespace *string, network, username string,
	filterBy, filterValue, sortBy, sortDesc string,
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
			&types.User{}, rx, listUserPtrs, // __CYLONIX_MOD__ adapted to new ListUsers signature
			idList, namespace, "network", network, "", false, false,
			"users", nil, nil,
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
		// __BEGIN_CYLONIX_MOD__
		// The upstream Route table was dropped in v0.26; approval of routes is
		// now denormalised onto Node.ApprovedRoutes. There is no per-route
		// network column to update here any more.
		// __END_CYLONIX_MOD__
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

// GetUser looks up a user by Name. Cylonix stores the tenant-scoped UUID in
// User.Name, so this is the primary way cylonix callers resolve users from
// strings. Returns ErrUserNotFound if no matching user exists.
func (hsdb *HSDatabase) GetUser(name string) (*types.User, error) {
	return GetUser(hsdb.DB, name)
}

func GetUser(tx *gorm.DB, name string) (*types.User, error) {
	user := types.User{}
	if result := tx.First(&user, "name = ?", name); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

func (hsdb *HSDatabase) GetUserByLoginName(namespace, loginName string) (*types.User, error) {
	var user types.User
	if err := hsdb.DB.First(&user, "login_name = ? AND namespace = ?", loginName, namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// __END_CYLONIX_MOD__

// CreateUser creates a new User. Returns error if could not be created
// or another user already exists.
func CreateUser(tx *gorm.DB, user types.User) (*types.User, error) {
	if err := util.ValidateHostname(user.Name); err != nil {
		return nil, err
	}

	// __BEGIN_CYLONIX_ADD__
	// Cylonix users are keyed by their globally unique Name (UUID); reject up
	// front rather than relying on a DB-level unique violation.
	existing := types.User{}
	if err := tx.Where("name = ?", user.Name).First(&existing).Error; err == nil {
		return nil, ErrUserExists
	}
	// __END_CYLONIX_ADD__

	if err := tx.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &user, nil
}

func (hsdb *HSDatabase) DestroyUser(uid types.UserID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyUser(tx, uid)
	})
}

// DestroyUser destroys a User. Returns error if the User does
// not exist or if there are nodes associated with it.
func DestroyUser(tx *gorm.DB, uid types.UserID) error {
	user, err := GetUserByID(tx, uid)
	if err != nil {
		return err
	}

	nodes, err := ListNodesByUser(tx, uid)
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

	keys, err := ListPreAuthKeys(tx)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = DestroyPreAuthKey(tx, key.ID)
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

func (hsdb *HSDatabase) RenameUser(uid types.UserID, newName string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RenameUser(tx, uid, newName)
	})
}

var ErrCannotChangeOIDCUser = errors.New("cannot edit OIDC user")

// RenameUser renames a User. Returns error if the User does
// not exist or if another User exists with the new name.
func RenameUser(tx *gorm.DB, uid types.UserID, newName string) error {
	var err error
	oldUser, err := GetUserByID(tx, uid)
	if err != nil {
		return err
	}
	if err = util.ValidateHostname(newName); err != nil {
		return err
	}

	if oldUser.Provider == util.RegisterMethodOIDC {
		return ErrCannotChangeOIDCUser
	}

	oldUser.Name = newName

	err = tx.Updates(&oldUser).Error
	if err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) GetUserByID(uid types.UserID) (*types.User, error) {
	return GetUserByID(hsdb.DB, uid)
}

func GetUserByID(tx *gorm.DB, uid types.UserID) (*types.User, error) {
	user := types.User{}
	if result := tx.First(&user, "id = ?", uid); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (hsdb *HSDatabase) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUserByOIDCIdentifier(rx, id)
	})
}

func GetUserByOIDCIdentifier(tx *gorm.DB, id string) (*types.User, error) {
	user := types.User{}
	if result := tx.First(&user, "provider_identifier = ?", id); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (hsdb *HSDatabase) ListUsers(where ...*types.User) ([]types.User, error) {
	return ListUsers(hsdb.DB, where...)
}

// ListUsers gets all the existing users.
func ListUsers(tx *gorm.DB, where ...*types.User) ([]types.User, error) {
	if len(where) > 1 {
		return nil, fmt.Errorf("expect 0 or 1 where User structs, got %d", len(where))
	}

	var user *types.User
	if len(where) == 1 {
		user = where[0]
	}

	users := []types.User{}
	if err := tx.Where(user).Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}

// __BEGIN_CYLONIX_ADD__
// listUserPtrs is the pointer-slice variant used by cylonix's ListWithOptions
// generic helper, which needs a callback returning []*types.User.
func listUserPtrs(tx *gorm.DB) ([]*types.User, error) {
	users, err := ListUsers(tx)
	if err != nil {
		return nil, err
	}
	out := make([]*types.User, len(users))
	for i := range users {
		out[i] = &users[i]
	}
	return out, nil
}

// __END_CYLONIX_ADD__

// GetUserByName returns a user if the provided username is
// unique, and otherwise an error.
func (hsdb *HSDatabase) GetUserByName(name string) (*types.User, error) {
	users, err := hsdb.ListUsers(&types.User{Name: name})
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, ErrUserNotFound
	}

	if len(users) != 1 {
		return nil, fmt.Errorf("expected exactly one user, found %d", len(users))
	}

	return &users[0], nil
}

// ListNodesByUser gets all the nodes in a given user.
func ListNodesByUser(tx *gorm.DB, uid types.UserID) (types.Nodes, error) {
	nodes := types.Nodes{}

	uidPtr := uint(uid)

	err := tx.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where(&types.Node{UserID: &uidPtr}).Find(&nodes).Error
	if err != nil {
		return nil, err
	}

	return nodes, nil
}

// __BEGIN_CYLONIX_ADD__
func (hsdb *HSDatabase) AssignNodeToUser(node *types.Node, username string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return AssignNodeToUser(tx, node, username)
	})
}

// AssignNodeToUser assigns a Node to a user.
func AssignNodeToUser(tx *gorm.DB, node *types.Node, username string) error {
	if err := util.ValidateHostname(username); err != nil {
		return err
	}
	user, err := GetUser(tx, username)
	if err != nil {
		return err
	}
	node.User = user
	v, _ := json.Marshal(node.Hostinfo)
	node.DebugLog().Str("HostInfo", string(v)).Msg("Saving node")

	if result := tx.Save(&node); result.Error != nil {
		return result.Error
	}
	return nil
}

// __END_CYLONIX_ADD__

func (hsdb *HSDatabase) CreateUserForTest(name ...string) *types.User {
	if !testing.Testing() {
		panic("CreateUserForTest can only be called during tests")
	}

	userName := "testuser"
	if len(name) > 0 && name[0] != "" {
		userName = name[0]
	}

	user, err := hsdb.CreateUser(types.User{Name: userName})
	if err != nil {
		panic(fmt.Sprintf("failed to create test user: %v", err))
	}

	return user
}

func (hsdb *HSDatabase) CreateUsersForTest(count int, namePrefix ...string) []*types.User {
	if !testing.Testing() {
		panic("CreateUsersForTest can only be called during tests")
	}

	prefix := "testuser"
	if len(namePrefix) > 0 && namePrefix[0] != "" {
		prefix = namePrefix[0]
	}

	users := make([]*types.User, count)
	for i := range count {
		name := prefix + "-" + strconv.Itoa(i)
		users[i] = hsdb.CreateUserForTest(name)
	}

	return users
}
