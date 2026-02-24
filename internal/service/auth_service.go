package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/pkg/crypto"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

// TokenSet represents a set of tokens returned after authentication.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type AuthService interface {
	Register(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData, inviteCode string) (*model.User, error)
	Login(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData) (*TokenSet, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error)
	Logout(ctx context.Context, refreshToken string) error
}

type authService struct {
	userRepo      repository.UserRepository
	identityRepo  repository.IdentityRepository
	inviteRepo    repository.InviteCodeRepository
	stateStore    repository.StateStore
	jwtManager    *jwtpkg.Manager
	inviteEnabled bool
}

func NewAuthService(
	userRepo repository.UserRepository,
	identityRepo repository.IdentityRepository,
	inviteRepo repository.InviteCodeRepository,
	stateStore repository.StateStore,
	jwtManager *jwtpkg.Manager,
	inviteEnabled bool,
) AuthService {
	return &authService{
		userRepo:      userRepo,
		identityRepo:  identityRepo,
		inviteRepo:    inviteRepo,
		stateStore:    stateStore,
		jwtManager:    jwtManager,
		inviteEnabled: inviteEnabled,
	}
}

func (s *authService) Register(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData, inviteCode string) (*model.User, error) {
	// 1. Validate invite code if enabled
	if s.inviteEnabled {
		if inviteCode == "" {
			return nil, ErrInviteCodeRequired
		}
		invite, err := s.inviteRepo.GetByCode(ctx, inviteCode)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrInviteCodeInvalid
			}
			return nil, fmt.Errorf("failed to check invite code: %w", err)
		}
		if invite.ExpiresAt != nil && time.Now().After(*invite.ExpiresAt) {
			return nil, ErrInviteCodeInvalid
		}
		if invite.UsedCount >= invite.MaxUses {
			return nil, ErrInviteCodeExhausted
		}
	}

	// 2. Check identity uniqueness
	_, err := s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, identifier)
	if err == nil {
		return nil, ErrIdentityAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check identity: %w", err)
	}

	// 3. Process credentials
	processed, err := processCredentialData(identityType, credentialData)
	if err != nil {
		return nil, err
	}

	// 4. Create user
	user := &model.User{Status: model.UserStatusActive}
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// 5. Create identity
	identity := &model.UserIdentity{
		UserID:         user.ID,
		IdentityType:   identityType,
		Identifier:     identifier,
		CredentialData: processed,
	}
	if err := s.identityRepo.Create(ctx, identity); err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// 6. Increment invite code usage
	if s.inviteEnabled && inviteCode != "" {
		if err := s.inviteRepo.IncrementUsedCount(ctx, inviteCode); err != nil {
			return nil, fmt.Errorf("failed to increment invite code: %w", err)
		}
	}

	return user, nil
}

func (s *authService) Login(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData) (*TokenSet, error) {
	// 1. Find identity
	identity, err := s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, identifier)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find identity: %w", err)
	}

	// 2. Check user status
	user, err := s.userRepo.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserDisabled
	}

	// 3. Verify credentials
	switch identityType {
	case model.IdentityTypePassword:
		password, ok := credentialData["password"].(string)
		if !ok || password == "" {
			return nil, ErrInvalidCredentials
		}
		hash, ok := identity.CredentialData["hash"].(string)
		if !ok {
			return nil, fmt.Errorf("corrupted credential data")
		}
		if !crypto.CheckPassword(password, hash) {
			return nil, ErrInvalidCredentials
		}
	default:
		return nil, ErrUnsupportedIdentity
	}

	// 4. Issue tokens
	return s.issueTokenSet(ctx, user.ID)
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	// 1. Validate refresh token
	claims, err := s.jwtManager.Validate(refreshToken)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}
	if claims.TokenType != jwtpkg.TokenTypeRefresh {
		return nil, ErrRefreshTokenInvalid
	}

	// 2. Check JTI in StateStore
	stateKey := "refresh_token:" + claims.ID
	value, err := s.stateStore.Get(ctx, stateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check refresh token state: %w", err)
	}
	if value == nil {
		return nil, ErrRefreshTokenInvalid
	}

	// 3. Check user status
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserDisabled
	}

	// 4. Token rotation: delete old JTI
	_ = s.stateStore.Delete(ctx, stateKey)

	// 5. Issue new token set
	return s.issueTokenSet(ctx, user.ID)
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	// 1. Validate refresh token
	claims, err := s.jwtManager.Validate(refreshToken)
	if err != nil {
		return ErrRefreshTokenInvalid
	}
	if claims.TokenType != jwtpkg.TokenTypeRefresh {
		return ErrRefreshTokenInvalid
	}

	// 2. Delete JTI from StateStore
	stateKey := "refresh_token:" + claims.ID
	return s.stateStore.Delete(ctx, stateKey)
}

// issueTokenSet generates access, refresh, and ID tokens and stores refresh JTI in StateStore.
func (s *authService) issueTokenSet(ctx context.Context, userID uuid.UUID) (*TokenSet, error) {
	accessToken, err := s.jwtManager.GenerateAccessToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshClaims, err := s.jwtManager.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	idToken, err := s.jwtManager.GenerateIDToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate id token: %w", err)
	}

	// Store refresh token JTI in StateStore
	stateKey := "refresh_token:" + refreshClaims.ID
	ttl := time.Until(refreshClaims.ExpiresAt.Time)
	if err := s.stateStore.Set(ctx, stateKey, []byte(userID.String()), ttl); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenSet{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresIn:    int64(s.jwtManager.AccessTokenTTL().Seconds()),
	}, nil
}

// processCredentialData processes raw credentials based on identity type.
func processCredentialData(identityType model.IdentityType, raw model.CredentialData) (model.CredentialData, error) {
	switch identityType {
	case model.IdentityTypePassword:
		password, ok := raw["password"].(string)
		if !ok || password == "" {
			return nil, errors.New("password is required")
		}
		if len(password) < 8 {
			return nil, errors.New("password must be at least 8 characters")
		}
		hash, err := crypto.HashPassword(password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		return model.CredentialData{"hash": hash}, nil
	default:
		return raw, nil
	}
}

// ensure authService implements AuthService
var _ AuthService = (*authService)(nil)
