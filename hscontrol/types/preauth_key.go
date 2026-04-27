package types

import (
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type PAKError string

func (e PAKError) Error() string { return string(e) }

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID uint64 `gorm:"primary_key"`

	// Legacy plaintext key (for backwards compatibility).
	Key string

	// New bcrypt-based authentication.
	Prefix string
	Hash   []byte // bcrypt

	// For tagged keys: UserID tracks who created the key (informational).
	// For user-owned keys: UserID tracks the node owner.
	// Can be nil for system-created tagged keys.
	UserID *uint
	User   *User `gorm:"constraint:OnDelete:SET NULL;"`

	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`

	// Tags to assign to nodes registered with this key.
	// Tags are copied to the node during registration.
	// If non-empty, this creates tagged nodes (not user-owned).
	Tags []string `gorm:"serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time

	// __BEGIN_CYLONIX_MOD__
	Namespace   string // cylonix tenant scoping
	IPv4        string // optional ipv4 address requested at registration
	IPv6        string // optional ipv6 address requested at registration
	Description string // free-text operator description
	// __END_CYLONIX_MOD__
}

// PreAuthKeyNew is returned once when the key is created. It carries the
// plaintext secret so callers can hand it to a node. After creation, only the
// prefix is retained server-side.
type PreAuthKeyNew struct {
	ID         uint64 `gorm:"primary_key"`
	Key        string
	Reusable   bool
	Ephemeral  bool
	Tags       []string
	Expiration *time.Time
	CreatedAt  *time.Time
	User       *User // Can be nil for system-created tagged keys.

	// __BEGIN_CYLONIX_MOD__
	Namespace   string
	IPv4        string
	IPv6        string
	Description string
	// __END_CYLONIX_MOD__
}

func (key *PreAuthKeyNew) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		Id:        key.ID,
		Key:       key.Key,
		User:      nil, // Will be set below if not nil.
		Reusable:  key.Reusable,
		Ephemeral: key.Ephemeral,
		AclTags:   key.Tags,
		// __BEGIN_CYLONIX_MOD__
		Namespace:   key.Namespace,
		Ipv4:        key.IPv4,
		Ipv6:        key.IPv6,
		Description: key.Description,
		// __END_CYLONIX_MOD__
	}

	if key.User != nil {
		protoKey.User = key.User.Proto()
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}

func (key *PreAuthKey) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      nil, // Will be set below if not nil.
		Id:        key.ID,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
		AclTags:   key.Tags,
		// __BEGIN_CYLONIX_MOD__
		Namespace:   key.Namespace,
		Ipv4:        key.IPv4,
		Ipv6:        key.IPv6,
		Description: key.Description,
		// __END_CYLONIX_MOD__
	}

	if key.User != nil {
		protoKey.User = key.User.Proto()
	}

	// For new bcrypt keys (with prefix/hash), show the prefix so users can
	// identify the key. For legacy keys (with plaintext key), show the full
	// key for backwards compatibility.
	if key.Prefix != "" {
		protoKey.Key = "hskey-auth-" + key.Prefix + "-***"
	} else if key.Key != "" {
		// Legacy key - show full key for backwards compatibility.
		// TODO: Consider hiding this in a future major version.
		protoKey.Key = key.Key
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}

// __BEGIN_CYLONIX_MOD__
// FromProto rehydrates a PreAuthKey from its protobuf representation. Cylonix
// uses this on the manager side to reconstruct keys returned from
// CreatePreAuthKey/ListPreAuthKeys RPCs.
//
// Note: upstream v0.28 keys created via CreatePreAuthKey now carry bcrypt
// Prefix+Hash, and the plaintext Key is only returned in PreAuthKeyNew at
// creation time. For legacy plaintext keys, Key is populated as before.
func (key *PreAuthKey) FromProto(p *v1.PreAuthKey) error {
	*key = PreAuthKey{
		ID:          p.GetId(),
		Key:         p.GetKey(),
		Ephemeral:   p.GetEphemeral(),
		Reusable:    p.GetReusable(),
		Used:        p.GetUsed(),
		Tags:        append([]string(nil), p.GetAclTags()...),
		Namespace:   p.GetNamespace(),
		IPv4:        p.GetIpv4(),
		IPv6:        p.GetIpv6(),
		Description: p.GetDescription(),
	}

	if p.GetUser() != nil {
		var u User
		u.FromProto(p.GetUser())
		key.User = &u
		if u.ID != 0 {
			uid := uint(u.ID)
			key.UserID = &uid
		}
	}

	if p.Expiration.IsValid() {
		t := p.Expiration.AsTime()
		key.Expiration = &t
	}

	if p.CreatedAt.IsValid() {
		t := p.CreatedAt.AsTime()
		key.CreatedAt = &t
	}

	return nil
}

// __END_CYLONIX_MOD__

// Validate checks whether a pre-auth key is in a usable state.
func (pak *PreAuthKey) Validate() error {
	if pak == nil {
		return PAKError("invalid authkey")
	}

	log.Debug().
		Caller().
		Str("key", pak.Key).
		Bool("hasExpiration", pak.Expiration != nil).
		Time("expiration", func() time.Time {
			if pak.Expiration != nil {
				return *pak.Expiration
			}
			return time.Time{}
		}()).
		Time("now", time.Now()).
		Bool("reusable", pak.Reusable).
		Bool("used", pak.Used).
		Msg("PreAuthKey.Validate: checking key")

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return PAKError("authkey expired")
	}

	// Reusable keys can be validated without checking Used.
	if pak.Reusable {
		return nil
	}

	if pak.Used {
		return PAKError("authkey already used")
	}

	return nil
}

// IsTagged returns true if this PreAuthKey creates tagged nodes.
// When a PreAuthKey has tags, nodes registered with it will be tagged nodes.
func (pak *PreAuthKey) IsTagged() bool {
	return len(pak.Tags) > 0
}
