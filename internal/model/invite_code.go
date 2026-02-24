package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InviteCode struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Code      string         `gorm:"type:varchar(64);uniqueIndex;not null" json:"code"`
	MaxUses   int            `gorm:"not null;default:1" json:"max_uses"`
	UsedCount int            `gorm:"not null;default:0" json:"used_count"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	CreatedBy uuid.UUID      `gorm:"type:uuid;not null" json:"created_by"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func (InviteCode) TableName() string { return "invite_codes" }
