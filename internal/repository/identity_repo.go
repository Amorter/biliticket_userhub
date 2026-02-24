package repository

import (
	"context"

	"github.com/google/uuid"

	"biliticket/userhub/internal/model"
)

type IdentityRepository interface {
	Create(ctx context.Context, identity *model.UserIdentity) error
	GetByTypeAndIdentifier(ctx context.Context, idType model.IdentityType, identifier string) (*model.UserIdentity, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]model.UserIdentity, error)
	Update(ctx context.Context, identity *model.UserIdentity) error
	Delete(ctx context.Context, id uuid.UUID) error
}
