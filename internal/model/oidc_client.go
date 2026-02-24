package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

// StringSlice is a helper type for storing []string as JSONB in PostgreSQL.
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("StringSlice.Scan: type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, s)
}

type OIDCClient struct {
	ClientID      string         `gorm:"type:varchar(128);primaryKey" json:"client_id"`
	ClientSecret  string         `gorm:"type:varchar(256);not null" json:"-"`
	Name          string         `gorm:"type:varchar(256);not null" json:"name"`
	RedirectURIs  StringSlice    `gorm:"type:jsonb" json:"redirect_uris"`
	AllowedScopes StringSlice    `gorm:"type:jsonb" json:"allowed_scopes"`
	IsFirstParty  bool           `gorm:"not null;default:false" json:"is_first_party"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func (OIDCClient) TableName() string { return "oidc_clients" }
