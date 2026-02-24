package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type IdentityType string

const (
	IdentityTypePassword IdentityType = "password"
	IdentityTypeGitHub   IdentityType = "github"
	IdentityTypeGoogle   IdentityType = "google"
	IdentityTypePasskey  IdentityType = "passkey"
	IdentityTypeWeChat   IdentityType = "wechat"
)

// CredentialData is a JSON blob stored in the credential_data column.
type CredentialData map[string]interface{}

func (cd CredentialData) Value() (driver.Value, error) {
	if cd == nil {
		return nil, nil
	}
	return json.Marshal(cd)
}

func (cd *CredentialData) Scan(value interface{}) error {
	if value == nil {
		*cd = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("CredentialData.Scan: type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, cd)
}

type UserIdentity struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	IdentityType   IdentityType   `gorm:"type:varchar(32);not null" json:"identity_type"`
	Identifier     string         `gorm:"type:varchar(512);not null" json:"identifier"`
	CredentialData CredentialData `gorm:"type:jsonb" json:"credential_data,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (UserIdentity) TableName() string { return "user_identities" }
