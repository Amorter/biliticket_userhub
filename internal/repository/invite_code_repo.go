package repository

import (
	"context"

	"biliticket/userhub/internal/model"
)

type InviteCodeRepository interface {
	Create(ctx context.Context, code *model.InviteCode) error
	GetByCode(ctx context.Context, code string) (*model.InviteCode, error)
	IncrementUsedCount(ctx context.Context, code string) error
}
