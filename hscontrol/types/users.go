package types

import (
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// User is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or users
// that contain our machines.
type User struct {
	gorm.Model
	Name string `gorm:"unique"`

	// __BEGIN_CYLONIX_MOD__
	// Since name field is unique and used extensively as a unique field in
	// headscale, we use it to store the uuid field instead for multi-tenancy
	// support. The real username for multi-tenant deployment is set in the
	// LoginName field instead. LoginName is uninque for a namespace/tenant.
	LoginName *string `gorm:"unique:namespace_login"`
	Namespace *string `gorm:"unique:namespace_login"`
	// __END_CYLONIX_MOD__
}

// TODO(kradalby): See if we can fill in Gravatar here
func (u *User) profilePicURL() string {
	return ""
}

func (u *User) TailscaleUser(cfg *Config) *tailcfg.User {
	// __BEGIN_CYLONIX_MOD__
	if cfg != nil && cfg.NodeHandler != nil {
		user := cfg.NodeHandler.User(u)
		if user != nil {
			return user
		}
	}
	// __END_CYLONIX_MOD__
	user := tailcfg.User{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Name,
		DisplayName:   u.Name,
		ProfilePicURL: u.profilePicURL(),
		Logins:        []tailcfg.LoginID{},
		Created:       u.CreatedAt,
	}

	return &user
}

func (u *User) TailscaleLogin(cfg *Config) *tailcfg.Login {
	// __BEGIN_CYLONIX_MOD__
	if cfg != nil && cfg.NodeHandler != nil {
		login := cfg.NodeHandler.UserLogin(u)
		if login != nil {
			return login
		}
	}
	// __END_CYLONIX_MOD__
	login := tailcfg.Login{
		ID: tailcfg.LoginID(u.ID),
		// TODO(kradalby): this should reflect registration method.
		Provider:      "",
		LoginName:     u.Name,
		DisplayName:   u.Name,
		ProfilePicURL: u.profilePicURL(),
	}

	return &login
}

func (u *User) TailscaleUserProfile(cfg *Config) tailcfg.UserProfile {
	// __BEGIN_CYLONIX_MOD__
	if cfg != nil && cfg.NodeHandler != nil {
		p := cfg.NodeHandler.UserProfile(u)
		if p != nil {
			return *p
		}
	}
	// __END_CYLONIX_MOD__
	return tailcfg.UserProfile{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Name,
		DisplayName:   u.Name,
		ProfilePicURL: u.profilePicURL(),
	}
}

func (n *User) Proto() *v1.User {
	// __BEGIN_CYLONIX_MOD__
	var namespace, loginName string
	if n.Namespace != nil {
		namespace = *n.Namespace
	}
	if n.LoginName != nil {
		loginName = *n.LoginName
	}
	// __END_CYLONIX_MOD__
	return &v1.User{
		Id:        strconv.FormatUint(uint64(n.ID), util.Base10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
		LoginName: loginName, // __CYLONIX_MOD__
		Namespace: namespace, // __CYLONIX_MOD__
	}
}

// __BEGIN_CYLONIX_MOD__
func (n *User) FromProto(v1User *v1.User) error {
	id, err := strconv.ParseUint(v1User.Id, util.Base10, util.BitSize64)
	if err != nil {
		return err
	}
	var namespace, loginName *string
	if v1User.Namespace != "" {
		namespace = &v1User.Namespace
	}
	if v1User.LoginName != "" {
		loginName = &v1User.LoginName
	}

	n.ID = uint(id)
	n.Name = v1User.Name
	n.CreatedAt = v1User.CreatedAt.AsTime()
	n.Namespace = namespace
	n.LoginName = loginName
	return nil
}
// __END_CYLONIX_MOD__
