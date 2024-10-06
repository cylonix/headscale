package types

import (
	"context"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// __BEGIN_CYLONIX_MOD__
// APIKey scope describes the scope an api key is authorized to access.

type AuthScopeType string

const (
	AuthScopeTypeFull      = AuthScopeType("full")      // Full access
	AuthScopeTypeNamespace = AuthScopeType("namespace") // matching a namespace
	AuthScopeTypeUser      = AuthScopeType("user")      // Matching a username
)

type AuthNamespaceScopedRequest interface {
	GetNamespace() string
}
type AuthUserScopedRequest interface {
	GetUser() string
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
}

func NewAuthScope(namespace, user string) *AuthScope {
	return &AuthScope{
		namespace: namespace,
		user:      user,
	}
}

func (s *AuthScope) GetNamespace() string {
	return s.namespace
}

func (s *AuthScope) GetUser() string {
	return s.user
}

func (key *APIKey) Auth(r interface{}) bool {
	if key == nil {
		return false
	}
	log.Debug().
		Str("scope-type", string(key.ScopeType)).
		Str("scope-value", key.ScopeValue).
		Msg("Auth Scope")
	switch key.ScopeType {
	case AuthScopeTypeFull:
		return true
	case AuthScopeTypeNamespace:
		s, ok := r.(AuthNamespaceScopedRequest)
		if ok {
			log.Debug().
				Str("authorized-scope", key.ScopeValue).
				Str("requested-scope", s.GetNamespace()).
				Msg("Auth Namespace Scope")
		}
		return ok && (s.GetNamespace() == key.ScopeValue)
	case AuthScopeTypeUser:
		s, ok := r.(AuthUserScopedRequest)
		if ok {
			log.Debug().
				Str("authorized-scope", key.ScopeValue).
				Str("requested-scope", s.GetUser()).
				Msg("Auth User Scope")
		}
		return ok && (s.GetUser() == key.ScopeValue)
	}
	return false
}

// __END_CYLONIX_MOD__

// APIKey describes the datamodel for API keys used to remotely authenticate with
// headscale.
type APIKey struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	// __BEGIN_CYLONIX_MOD__
	ScopeType  AuthScopeType
	ScopeValue string
	UserID     *uint
	User       *User
	Namespace  string
	// __END_CYLONIX_MOD__

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

func (key *APIKey) Proto() *v1.ApiKey {
	protoKey := v1.ApiKey{
		Id:     key.ID,
		Prefix: key.Prefix,
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

	// __BEGIN_CYLONIX_MOD__
	if key.User != nil {
		protoKey.User = key.User.Proto()
	}
	protoKey.Namespace = key.Namespace
	// __END_CYLONIX_MOD__

	return &protoKey
}

// __BEGIN_CYLONIX_MOD__
func (key *APIKey) Username() string {
	if key == nil || key.User == nil {
		return ""
	}
	return key.User.Name
}
// __END_CYLONIX_MOD__