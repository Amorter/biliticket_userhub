package repository

import (
	"context"

	"gorm.io/gorm"

	"biliticket/userhub/internal/model"
)

type pgInviteCodeRepository struct {
	db *gorm.DB
}

func NewPGInviteCodeRepository(db *gorm.DB) InviteCodeRepository {
	return &pgInviteCodeRepository{db: db}
}

func (r *pgInviteCodeRepository) Create(ctx context.Context, code *model.InviteCode) error {
	return r.db.WithContext(ctx).Create(code).Error
}

func (r *pgInviteCodeRepository) GetByCode(ctx context.Context, code string) (*model.InviteCode, error) {
	var inviteCode model.InviteCode
	if err := r.db.WithContext(ctx).Where("code = ?", code).First(&inviteCode).Error; err != nil {
		return nil, err
	}
	return &inviteCode, nil
}

func (r *pgInviteCodeRepository) IncrementUsedCount(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).
		Model(&model.InviteCode{}).
		Where("code = ?", code).
		UpdateColumn("used_count", gorm.Expr("used_count + 1")).
		Error
}

func (r *pgInviteCodeRepository) List(ctx context.Context) ([]model.InviteCode, error) {
	var codes []model.InviteCode
	if err := r.db.WithContext(ctx).Order("created_at DESC").Find(&codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}
