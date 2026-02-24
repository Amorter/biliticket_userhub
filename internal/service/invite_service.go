package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
)

type InviteService interface {
	CreateInviteCode(ctx context.Context, createdBy uuid.UUID, maxUses int, expiresAt *time.Time) (*model.InviteCode, error)
	ListInviteCodes(ctx context.Context) ([]model.InviteCode, error)
}

type inviteService struct {
	inviteRepo repository.InviteCodeRepository
}

func NewInviteService(inviteRepo repository.InviteCodeRepository) InviteService {
	return &inviteService{inviteRepo: inviteRepo}
}

func (s *inviteService) CreateInviteCode(ctx context.Context, createdBy uuid.UUID, maxUses int, expiresAt *time.Time) (*model.InviteCode, error) {
	if maxUses <= 0 {
		maxUses = 1
	}

	code, err := generateInviteCode()
	if err != nil {
		return nil, fmt.Errorf("generate invite code: %w", err)
	}

	inviteCode := &model.InviteCode{
		Code:      code,
		MaxUses:   maxUses,
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
	}
	if err := s.inviteRepo.Create(ctx, inviteCode); err != nil {
		return nil, fmt.Errorf("create invite code: %w", err)
	}
	return inviteCode, nil
}

func (s *inviteService) ListInviteCodes(ctx context.Context) ([]model.InviteCode, error) {
	return s.inviteRepo.List(ctx)
}

// generateInviteCode creates a random 16-character hex invite code.
func generateInviteCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
