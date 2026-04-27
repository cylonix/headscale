package types

import (
	"context"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// __BEGIN_CYLONIX_ADD__
// APIKey scope describes the scope an api key is authorized to access.

type AuthScopeType string

const (
	AuthScopeTypeFull      = AuthScopeType("full")      // Full access
	AuthScopeTypeNamespace = AuthScopeType("namespace") // matching a namespace
	AuthScopeTypeNetwork   = AuthScopeType("network")   // matching a network
	AuthScopeTypeUser      = AuthScopeType("user")      // matching a username
	AuthScopeTypeNone      = AuthScopeType("none")      // No access
)

type AuthNamespaceScopedRequest interface {
	GetNamespace() string
}
type AuthUserScopedRequest interface {
	GetUser() string
}

type AuthNetworkScopedRequest interface {
	GetNetwork() string
}

type authScopeTypeContextKeyType struct{}

func WithFullAuthScope(ctx context.Context) context.Context {
	return context.WithValue(
		ctx,
		authScopeTypeContextKeyType{},
		AuthScopeTypeFull,
	)
}

func IsWithFullAuthScope(ctx context.Context) bool {
	scope := ctx.Value(authScopeTypeContextKeyType{})
	s, ok := scope.(AuthScopeType)
	return ok && s == AuthScopeTypeFull
}

type AuthScope struct {
	namespace string
	user      string
	network   string
}

func NewAuthScope(namespace, user, network string) *AuthScope {
	return &AuthScope{
		namespace: namespace,
		user:      user,
		network:   network,
	}
}

func (s *AuthScope) GetNamespace() string { return s.namespace }
func (s *AuthScope) GetUser() string      { return s.user }
func (s *AuthScope) GetNetwork() string   { return s.network }

func (key *APIKey) Auth(r interface{}) (AuthScopeType, bool) {
	if key == nil {
		return AuthScopeTypeNone, false
	}
	if r == nil {
		return key.ScopeType, false
	}
	log.Debug().
		Str("scope-type", string(key.ScopeType)).
		Str("scope-value", key.ScopeValue).
		Msg("Auth Scope")
	switch key.ScopeType {
	case AuthScopeTypeFull:
		return AuthScopeTypeFull, true
	case AuthScopeTypeNamespace:
		s, ok := r.(AuthNamespaceScopedRequest)
		namespace := ""
		if ok {
			namespace = s.GetNamespace()
			log.Debug().
				Str("authorized-scope", key.ScopeValue).
				Str("requested-scope", namespace).
				Msg("Auth Namespace Scope")
		}
		return AuthScopeTypeNamespace, ok && namespace == key.ScopeValue && namespace != ""
	case AuthScopeTypeNetwork:
		s, ok := r.(AuthNetworkScopedRequest)
		network := ""
		if ok {
			network = s.GetNetwork()
			log.Debug().
				Str("authorized-scope", key.ScopeValue).
				Str("requested-scope", network).
				Msg("Auth network Scope")
		}
		return AuthScopeTypeNetwork, ok && network == key.ScopeValue && network != ""
	case AuthScopeTypeUser:
		s, ok := r.(AuthUserScopedRequest)
		user := ""
		if ok {
			user = s.GetUser()
			log.Debug().
				Str("authorized-scope", key.ScopeValue).
				Str("requested-scope", user).
				Msg("Auth User Scope")
		}
		return AuthScopeTypeUser, ok && user == key.ScopeValue && user != ""
	}
	return AuthScopeTypeNone, false
}

// __END_CYLONIX_ADD__

const (
	// NewAPIKeyPrefixLength is the length of the prefix for new API keys.
	NewAPIKeyPrefixLength = 12
	// LegacyAPIKeyPrefixLength is the length of the prefix for legacy API keys.
	LegacyAPIKeyPrefixLength = 7
)

// APIKey describes the datamodel for API keys used to remotely authenticate with
// headscale.
type APIKey struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	// __BEGIN_CYLONIX_ADD__
	ScopeType  AuthScopeType
	ScopeValue string
	UserID     *uint
	User       *User
	Network    string
	Namespace  string
	// __END_CYLONIX_ADD__

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

func (key *APIKey) Proto() *v1.ApiKey {
	protoKey := v1.ApiKey{
		Id: key.ID,
	}

	// Show prefix format: distinguish between new (12-char) and legacy (7-char) keys.
	if len(key.Prefix) == NewAPIKeyPrefixLength {
		// New format key (12-char prefix).
		protoKey.Prefix = "hskey-api-" + key.Prefix + "-***"
	} else {
		// Legacy format key (7-char prefix) or fallback.
		protoKey.Prefix = key.Prefix + "***"
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	if key.LastSeen != nil {
		protoKey.LastSeen = timestamppb.New(*key.LastSeen)
	}

	// __BEGIN_CYLONIX_ADD__
	if key.User != nil {
		protoKey.User = key.User.Proto()
	}
	protoKey.Namespace = key.Namespace
	protoKey.Network = key.Network
	// __END_CYLONIX_ADD__

	return &protoKey
}

// __BEGIN_CYLONIX_ADD__
// Username returns the headscale User.Name (which cylonix uses to carry its
// tenant-scoped user UUID). Empty if the key has no associated user.
func (key *APIKey) Username() string {
	if key == nil || key.User == nil {
		return ""
	}
	return key.User.Name
}

// __END_CYLONIX_ADD__
