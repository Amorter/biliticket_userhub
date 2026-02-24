package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
)

type IdentityService interface {
	BindIdentity(ctx context.Context, userID uuid.UUID, identityType model.IdentityType, identifier string, credentialData model.CredentialData) error
	UnbindIdentity(ctx context.Context, userID uuid.UUID, identityID uuid.UUID) error
	ListIdentities(ctx context.Context, userID uuid.UUID) ([]model.UserIdentity, error)
}

type identityService struct {
	identityRepo repository.IdentityRepository
}

func NewIdentityService(identityRepo repository.IdentityRepository) IdentityService {
	return &identityService{identityRepo: identityRepo}
}

func (s *identityService) BindIdentity(ctx context.Context, userID uuid.UUID, identityType model.IdentityType, identifier string, credentialData model.CredentialData) error {
	return errors.New("not implemented")
}

func (s *identityService) UnbindIdentity(ctx context.Context, userID uuid.UUID, identityID uuid.UUID) error {
	return errors.New("not implemented")
}

func (s *identityService) ListIdentities(ctx context.Context, userID uuid.UUID) ([]model.UserIdentity, error) {
	return nil, errors.New("not implemented")
}

var _ IdentityService = (*identityService)(nil)
