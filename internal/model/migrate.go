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

	// Composite unique index: only enforce on non-soft-deleted rows
	return db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_type_identifier " +
			"ON user_identities (identity_type, identifier) WHERE deleted_at IS NULL",
	).Error
}
