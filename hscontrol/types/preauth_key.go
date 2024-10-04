package types

import (
	"strconv"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID        uint64 `gorm:"primary_key"`
	Key       string
	UserID    uint
	User      User `gorm:"constraint:OnDelete:CASCADE;"`
	Reusable  bool
	Ephemeral bool               `gorm:"default:false"`
	Used      bool               `gorm:"default:false"`
	ACLTags   []PreAuthKeyACLTag `gorm:"constraint:OnDelete:CASCADE;"`

	CreatedAt  *time.Time
	Expiration *time.Time

	Namespace string // __CYLONIX_MOD__
}

// PreAuthKeyACLTag describes an autmatic tag applied to a node when registered with the associated PreAuthKey.
type PreAuthKeyACLTag struct {
	ID           uint64 `gorm:"primary_key"`
	PreAuthKeyID uint64
	Tag          string
}

func (key *PreAuthKey) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      key.User.Name,
		Id:        strconv.FormatUint(key.ID, util.Base10),
		Key:       key.Key,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
		AclTags:   make([]string, len(key.ACLTags)),

		UserDetail: key.User.Proto(), // __CYLONIX_MOD__
		Namespace:  key.Namespace,    // __CYLONIX_MOD__
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	for idx := range key.ACLTags {
		protoKey.AclTags[idx] = key.ACLTags[idx].Tag
	}

	return &protoKey
}

// __BEGIN_CYLONIX_MOD__
func (key *PreAuthKey) FromProto(p *v1.PreAuthKey) error {
	id, err := strconv.ParseUint(p.Id, util.Base10, util.BitSize64)
	if err != nil {
		return err
	}
	*key = PreAuthKey{
		User:      User{Name: p.User},
		ID:        id,
		Key:       p.Key,
		Ephemeral: p.Ephemeral,
		Reusable:  p.Reusable,
		Used:      p.Used,
		Namespace: p.Namespace,
	}

	if p.Expiration.IsValid() {
		t := p.Expiration.AsTime()
		key.Expiration = &t
	}

	if p.CreatedAt.IsValid() {
		t := p.CreatedAt.AsTime()
		key.CreatedAt = &t
	}

	var aclTags []PreAuthKeyACLTag
	for _, v := range p.AclTags {
		aclTags = append(aclTags, PreAuthKeyACLTag{PreAuthKeyID: id, Tag: v})
	}
	key.ACLTags = aclTags

	return nil
}
// __END_CYLONIX_MOD__