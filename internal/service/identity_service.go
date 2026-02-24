package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

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
	userRepo     repository.UserRepository
}

func NewIdentityService(identityRepo repository.IdentityRepository, userRepo repository.UserRepository) IdentityService {
	return &identityService{
		identityRepo: identityRepo,
		userRepo:     userRepo,
	}
}

func (s *identityService) BindIdentity(ctx context.Context, userID uuid.UUID, identityType model.IdentityType, identifier string, credentialData model.CredentialData) error {
	// 1. Check user exists and is active
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return ErrUserDisabled
	}

	// 2. Check identity not already taken
	_, err = s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, identifier)
	if err == nil {
		return ErrIdentityAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to check identity: %w", err)
	}

	// 3. Process credentials
	processed, err := processCredentialData(identityType, credentialData)
	if err != nil {
		return err
	}

	// 4. Create identity
	identity := &model.UserIdentity{
		UserID:         userID,
		IdentityType:   identityType,
		Identifier:     identifier,
		CredentialData: processed,
	}
	return s.identityRepo.Create(ctx, identity)
}

func (s *identityService) UnbindIdentity(ctx context.Context, userID uuid.UUID, identityID uuid.UUID) error {
	// 1. List all identities for user
	identities, err := s.identityRepo.ListByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to list identities: %w", err)
	}

	// 2. Must keep at least one
	if len(identities) <= 1 {
		return ErrCannotUnbindLast
	}

	// 3. Verify identity belongs to user
	found := false
	for _, id := range identities {
		if id.ID == identityID {
			found = true
			break
		}
	}
	if !found {
		return ErrIdentityNotOwned
	}

	// 4. Soft delete
	return s.identityRepo.Delete(ctx, identityID)
}

func (s *identityService) ListIdentities(ctx context.Context, userID uuid.UUID) ([]model.UserIdentity, error) {
	identities, err := s.identityRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list identities: %w", err)
	}

	// Sanitize credential data
	for i := range identities {
		identities[i].CredentialData = sanitizeCredentialData(identities[i].IdentityType, identities[i].CredentialData)
	}

	return identities, nil
}

func sanitizeCredentialData(identityType model.IdentityType, data model.CredentialData) model.CredentialData {
	switch identityType {
	case model.IdentityTypePassword:
		return nil
	case model.IdentityTypePasskey:
		if data == nil {
			return nil
		}
		sanitized := model.CredentialData{}
		if v, ok := data["credential_id"]; ok {
			sanitized["credential_id"] = v
		}
		return sanitized
	default:
		return data
	}
}

var _ IdentityService = (*identityService)(nil)
