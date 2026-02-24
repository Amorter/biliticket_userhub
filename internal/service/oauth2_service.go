package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/pkg/crypto"
)

var (
	ErrOAuth2ProviderNotConfigured = errors.New("oauth2 provider not configured")
	ErrOAuth2InvalidState          = errors.New("invalid or expired oauth2 state")
	ErrOAuth2TokenExchange         = errors.New("failed to exchange oauth2 code for token")
	ErrOAuth2UserInfo              = errors.New("failed to get oauth2 user info")
)

// oauth2StateData stores state for CSRF protection during OAuth2 flow.
type oauth2StateData struct {
	Provider    string `json:"provider"`
	RedirectURL string `json:"redirect_url"`
	Purpose     string `json:"purpose"` // "login" or "bind"
	UserID      string `json:"user_id,omitempty"`
}

type OAuth2Service interface {
	GetAuthorizationURL(ctx context.Context, provider string) (string, error)
	GetBindAuthorizationURL(ctx context.Context, provider string, userID uuid.UUID) (string, error)
	HandleCallback(ctx context.Context, provider, code, state string) (*TokenSet, error)
	HandleBindCallback(ctx context.Context, provider, code, state string) error
}

type oauth2Service struct {
	cfg          config.OAuth2Config
	identityRepo repository.IdentityRepository
	userRepo     repository.UserRepository
	stateStore   repository.StateStore
	authService  AuthService
}

func NewOAuth2Service(
	cfg config.OAuth2Config,
	identityRepo repository.IdentityRepository,
	userRepo repository.UserRepository,
	stateStore repository.StateStore,
	authService AuthService,
) OAuth2Service {
	return &oauth2Service{
		cfg:          cfg,
		identityRepo: identityRepo,
		userRepo:     userRepo,
		stateStore:   stateStore,
		authService:  authService,
	}
}

func (s *oauth2Service) getProviderConfig(provider string) (*config.OAuth2ProviderConfig, error) {
	switch provider {
	case "github":
		if s.cfg.GitHub.ClientID == "" {
			return nil, ErrOAuth2ProviderNotConfigured
		}
		return &s.cfg.GitHub, nil
	case "google":
		if s.cfg.Google.ClientID == "" {
			return nil, ErrOAuth2ProviderNotConfigured
		}
		return &s.cfg.Google, nil
	default:
		return nil, fmt.Errorf("unknown oauth2 provider: %s", provider)
	}
}

func (s *oauth2Service) GetAuthorizationURL(ctx context.Context, provider string) (string, error) {
	return s.buildAuthURL(ctx, provider, "login", "")
}

func (s *oauth2Service) GetBindAuthorizationURL(ctx context.Context, provider string, userID uuid.UUID) (string, error) {
	return s.buildAuthURL(ctx, provider, "bind", userID.String())
}

func (s *oauth2Service) buildAuthURL(ctx context.Context, provider, purpose, userID string) (string, error) {
	cfg, err := s.getProviderConfig(provider)
	if err != nil {
		return "", err
	}

	stateToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	stateData := oauth2StateData{
		Provider:    provider,
		RedirectURL: cfg.RedirectURL,
		Purpose:     purpose,
		UserID:      userID,
	}
	data, _ := json.Marshal(stateData)
	if err := s.stateStore.Set(ctx, "oauth2_state:"+stateToken, data, 10*time.Minute); err != nil {
		return "", fmt.Errorf("store state: %w", err)
	}

	authURL := s.getAuthEndpoint(provider)
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURL},
		"scope":         {strings.Join(cfg.Scopes, " ")},
		"state":         {stateToken},
		"response_type": {"code"},
	}

	return authURL + "?" + params.Encode(), nil
}

func (s *oauth2Service) getAuthEndpoint(provider string) string {
	switch provider {
	case "github":
		return "https://github.com/login/oauth/authorize"
	case "google":
		return "https://accounts.google.com/o/oauth2/v2/auth"
	default:
		return ""
	}
}

func (s *oauth2Service) HandleCallback(ctx context.Context, provider, code, state string) (*TokenSet, error) {
	stateData, err := s.validateAndConsumeState(ctx, state, provider, "login")
	if err != nil {
		return nil, err
	}
	_ = stateData

	subjectID, err := s.exchangeAndGetSubject(ctx, provider, code)
	if err != nil {
		return nil, err
	}

	identityType := providerToIdentityType(provider)
	identity, err := s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, subjectID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIdentityNotFound
		}
		return nil, fmt.Errorf("find identity: %w", err)
	}

	user, err := s.userRepo.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserDisabled
	}

	// Issue tokens via auth service's internal method
	// We call Login with the identity type but need to bypass credential check.
	// Instead, we directly use the issueTokenSet from authService.
	// Since authService is an interface, we cast to access the internal method.
	if as, ok := s.authService.(*authService); ok {
		return as.issueTokenSet(ctx, user.ID)
	}
	return nil, fmt.Errorf("internal error: cannot issue tokens")
}

func (s *oauth2Service) HandleBindCallback(ctx context.Context, provider, code, state string) error {
	stateData, err := s.validateAndConsumeState(ctx, state, provider, "bind")
	if err != nil {
		return err
	}

	userID, err := uuid.Parse(stateData.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id in state: %w", err)
	}

	subjectID, err := s.exchangeAndGetSubject(ctx, provider, code)
	if err != nil {
		return err
	}

	identityType := providerToIdentityType(provider)

	// Check identity not already taken
	_, err = s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, subjectID)
	if err == nil {
		return ErrIdentityAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("check identity: %w", err)
	}

	identity := &model.UserIdentity{
		UserID:       userID,
		IdentityType: identityType,
		Identifier:   subjectID,
		CredentialData: model.CredentialData{
			"provider": provider,
		},
	}
	return s.identityRepo.Create(ctx, identity)
}

func (s *oauth2Service) validateAndConsumeState(ctx context.Context, state, expectedProvider, expectedPurpose string) (*oauth2StateData, error) {
	data, err := s.stateStore.Get(ctx, "oauth2_state:"+state)
	if err != nil || data == nil {
		return nil, ErrOAuth2InvalidState
	}
	_ = s.stateStore.Delete(ctx, "oauth2_state:"+state)

	var stateData oauth2StateData
	if err := json.Unmarshal(data, &stateData); err != nil {
		return nil, ErrOAuth2InvalidState
	}
	if stateData.Provider != expectedProvider || stateData.Purpose != expectedPurpose {
		return nil, ErrOAuth2InvalidState
	}
	return &stateData, nil
}

func (s *oauth2Service) exchangeAndGetSubject(ctx context.Context, provider, code string) (string, error) {
	cfg, err := s.getProviderConfig(provider)
	if err != nil {
		return "", err
	}

	accessToken, err := s.exchangeCode(ctx, provider, code, cfg)
	if err != nil {
		return "", err
	}

	return s.getUserSubjectID(ctx, provider, accessToken)
}

func (s *oauth2Service) exchangeCode(_ context.Context, provider, code string, cfg *config.OAuth2ProviderConfig) (string, error) {
	var tokenURL string
	switch provider {
	case "github":
		tokenURL = "https://github.com/login/oauth/access_token"
	case "google":
		tokenURL = "https://oauth2.googleapis.com/token"
	}

	params := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURL},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", ErrOAuth2TokenExchange
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", ErrOAuth2TokenExchange
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ErrOAuth2TokenExchange
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", ErrOAuth2TokenExchange
	}
	if tokenResp.Error != "" || tokenResp.AccessToken == "" {
		return "", ErrOAuth2TokenExchange
	}

	return tokenResp.AccessToken, nil
}

func (s *oauth2Service) getUserSubjectID(_ context.Context, provider, accessToken string) (string, error) {
	var userURL string
	switch provider {
	case "github":
		userURL = "https://api.github.com/user"
	case "google":
		userURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	}

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return "", ErrOAuth2UserInfo
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", ErrOAuth2UserInfo
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ErrOAuth2UserInfo
	}

	switch provider {
	case "github":
		var user struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(body, &user); err != nil || user.ID == 0 {
			return "", ErrOAuth2UserInfo
		}
		return fmt.Sprintf("%d", user.ID), nil
	case "google":
		var user struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &user); err != nil || user.ID == "" {
			return "", ErrOAuth2UserInfo
		}
		return user.ID, nil
	}

	return "", ErrOAuth2UserInfo
}

func providerToIdentityType(provider string) model.IdentityType {
	switch provider {
	case "github":
		return model.IdentityTypeGitHub
	case "google":
		return model.IdentityTypeGoogle
	default:
		return model.IdentityType(provider)
	}
}
