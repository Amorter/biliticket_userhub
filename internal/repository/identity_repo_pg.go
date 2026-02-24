package repository

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"biliticket/userhub/internal/model"
)

type pgIdentityRepository struct {
	db *gorm.DB
}

func NewPGIdentityRepository(db *gorm.DB) IdentityRepository {
	return &pgIdentityRepository{db: db}
}

func (r *pgIdentityRepository) Create(ctx context.Context, identity *model.UserIdentity) error {
	return r.db.WithContext(ctx).Create(identity).Error
}

func (r *pgIdentityRepository) GetByTypeAndIdentifier(
	ctx context.Context, idType model.IdentityType, identifier string,
) (*model.UserIdentity, error) {
	var identity model.UserIdentity
	err := r.db.WithContext(ctx).
		Where("identity_type = ? AND identifier = ?", idType, identifier).
		First(&identity).Error
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func (r *pgIdentityRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]model.UserIdentity, error) {
	var identities []model.UserIdentity
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&identities).Error
	return identities, err
}

func (r *pgIdentityRepository) Update(ctx context.Context, identity *model.UserIdentity) error {
	return r.db.WithContext(ctx).Save(identity).Error
}

func (r *pgIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&model.UserIdentity{}, "id = ?", id).Error
}
