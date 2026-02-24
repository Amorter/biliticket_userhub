package service

import (
	"context"
	"errors"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
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
	return nil, errors.New("not implemented")
}

func (s *authService) Login(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData) (*TokenSet, error) {
	return nil, errors.New("not implemented")
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	return nil, errors.New("not implemented")
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	return errors.New("not implemented")
}

// ensure authService implements AuthService
var _ AuthService = (*authService)(nil)
