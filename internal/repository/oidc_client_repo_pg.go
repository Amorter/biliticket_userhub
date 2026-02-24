package repository

import (
	"context"

	"gorm.io/gorm"

	"biliticket/userhub/internal/model"
)

type pgOIDCClientRepository struct {
	db *gorm.DB
}

func NewPGOIDCClientRepository(db *gorm.DB) OIDCClientRepository {
	return &pgOIDCClientRepository{db: db}
}

func (r *pgOIDCClientRepository) Create(ctx context.Context, client *model.OIDCClient) error {
	return r.db.WithContext(ctx).Create(client).Error
}

func (r *pgOIDCClientRepository) GetByClientID(ctx context.Context, clientID string) (*model.OIDCClient, error) {
	var client model.OIDCClient
	if err := r.db.WithContext(ctx).First(&client, "client_id = ?", clientID).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *pgOIDCClientRepository) List(ctx context.Context) ([]model.OIDCClient, error) {
	var clients []model.OIDCClient
	err := r.db.WithContext(ctx).Find(&clients).Error
	return clients, err
}

func (r *pgOIDCClientRepository) Update(ctx context.Context, client *model.OIDCClient) error {
	return r.db.WithContext(ctx).Save(client).Error
}

func (r *pgOIDCClientRepository) Delete(ctx context.Context, clientID string) error {
	return r.db.WithContext(ctx).Delete(&model.OIDCClient{}, "client_id = ?", clientID).Error
}
