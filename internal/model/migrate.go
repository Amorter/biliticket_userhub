package model

import "gorm.io/gorm"

// AutoMigrate runs GORM auto-migration for all models and creates custom indexes.
func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&User{},
		&UserIdentity{},
		&OIDCClient{},
		&InviteCode{},
	); err != nil {
		return err
	}

	// Composite unique index: only enforce on non-soft-deleted rows.
	if err := db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_type_identifier " +
			"ON user_identities (identity_type, identifier) WHERE deleted_at IS NULL",
	).Error; err != nil {
		return err
	}

	// Case-insensitive unique username for non-soft-deleted users.
	if err := db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower " +
			"ON users ((lower(username))) WHERE deleted_at IS NULL AND username <> ''",
	).Error; err != nil {
		return err
	}

	// Case-insensitive unique email for non-soft-deleted users when email is not empty.
	return db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower_non_empty " +
			"ON users ((lower(email))) WHERE deleted_at IS NULL AND email <> ''",
	).Error
}
