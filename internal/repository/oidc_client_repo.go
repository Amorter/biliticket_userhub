package repository

import (
	"context"

	"biliticket/userhub/internal/model"
)

type OIDCClientRepository interface {
	Create(ctx context.Context, client *model.OIDCClient) error
	GetByClientID(ctx context.Context, clientID string) (*model.OIDCClient, error)
	List(ctx context.Context) ([]model.OIDCClient, error)
	Update(ctx context.Context, client *model.OIDCClient) error
	Delete(ctx context.Context, clientID string) error
}
