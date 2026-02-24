package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserStatus int

const (
	UserStatusActive   UserStatus = 1
	UserStatusDisabled UserStatus = 2
	UserStatusBanned   UserStatus = 3
)

type User struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Status    UserStatus     `gorm:"type:smallint;not null;default:1" json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	Identities []UserIdentity `gorm:"foreignKey:UserID" json:"identities,omitempty"`
}

func (User) TableName() string { return "users" }
