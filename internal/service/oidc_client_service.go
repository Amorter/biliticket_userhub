package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gorm.io/gorm"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/pkg/crypto"
)

var defaultOIDCScopes = []string{"openid", "profile", "email", "offline_access"}

type CreateOIDCClientInput struct {
	ClientID      string
	ClientSecret  string
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	IsFirstParty  bool
}

type UpdateOIDCClientInput struct {
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	IsFirstParty  bool
}

type CreatedOIDCClient struct {
	Client       *model.OIDCClient
	ClientSecret string
}

type OIDCClientService interface {
	Create(ctx context.Context, input CreateOIDCClientInput) (*CreatedOIDCClient, error)
	Get(ctx context.Context, clientID string) (*model.OIDCClient, error)
	List(ctx context.Context) ([]model.OIDCClient, error)
	Update(ctx context.Context, clientID string, input UpdateOIDCClientInput) (*model.OIDCClient, error)
	Delete(ctx context.Context, clientID string) error
	RotateSecret(ctx context.Context, clientID string) (string, error)
}

type oidcClientService struct {
	oidcClientRepo repository.OIDCClientRepository
}

func NewOIDCClientService(oidcClientRepo repository.OIDCClientRepository) OIDCClientService {
	return &oidcClientService{oidcClientRepo: oidcClientRepo}
}

func (s *oidcClientService) Create(ctx context.Context, input CreateOIDCClientInput) (*CreatedOIDCClient, error) {
	clientID, err := normalizeClientID(input.ClientID)
	if err != nil {
		return nil, err
	}

	name, err := normalizeClientName(input.Name)
	if err != nil {
		return nil, err
	}

	redirectURIs, err := normalizeRedirectURIs(input.RedirectURIs)
	if err != nil {
		return nil, err
	}

	allowedScopes, err := normalizeScopes(input.AllowedScopes, true)
	if err != nil {
		return nil, err
	}

	// Pre-check for friendlier conflict error.
	_, err = s.oidcClientRepo.GetByClientID(ctx, clientID)
	switch {
	case err == nil:
		return nil, ErrOIDCClientExists
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, fmt.Errorf("check oidc client existence: %w", err)
	}

	clientSecret := strings.TrimSpace(input.ClientSecret)
	if clientSecret == "" {
		clientSecret, err = crypto.GenerateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("generate client secret: %w", err)
		}
	}

	client := &model.OIDCClient{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Name:          name,
		RedirectURIs:  model.StringSlice(redirectURIs),
		AllowedScopes: model.StringSlice(allowedScopes),
		IsFirstParty:  input.IsFirstParty,
	}

	if err := s.oidcClientRepo.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("create oidc client: %w", err)
	}

	return &CreatedOIDCClient{
		Client:       client,
		ClientSecret: clientSecret,
	}, nil
}

func (s *oidcClientService) Get(ctx context.Context, clientID string) (*model.OIDCClient, error) {
	clientID, err := normalizeClientID(clientID)
	if err != nil {
		return nil, err
	}

	client, err := s.oidcClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOIDCClientNotFound
		}
		return nil, fmt.Errorf("get oidc client: %w", err)
	}
	return client, nil
}

func (s *oidcClientService) List(ctx context.Context) ([]model.OIDCClient, error) {
	clients, err := s.oidcClientRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list oidc clients: %w", err)
	}
	return clients, nil
}

func (s *oidcClientService) Update(ctx context.Context, clientID string, input UpdateOIDCClientInput) (*model.OIDCClient, error) {
	clientID, err := normalizeClientID(clientID)
	if err != nil {
		return nil, err
	}

	name, err := normalizeClientName(input.Name)
	if err != nil {
		return nil, err
	}

	redirectURIs, err := normalizeRedirectURIs(input.RedirectURIs)
	if err != nil {
		return nil, err
	}

	allowedScopes, err := normalizeScopes(input.AllowedScopes, false)
	if err != nil {
		return nil, err
	}

	client, err := s.oidcClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOIDCClientNotFound
		}
		return nil, fmt.Errorf("get oidc client for update: %w", err)
	}

	client.Name = name
	client.RedirectURIs = model.StringSlice(redirectURIs)
	client.AllowedScopes = model.StringSlice(allowedScopes)
	client.IsFirstParty = input.IsFirstParty

	if err := s.oidcClientRepo.Update(ctx, client); err != nil {
		return nil, fmt.Errorf("update oidc client: %w", err)
	}

	return client, nil
}

func (s *oidcClientService) Delete(ctx context.Context, clientID string) error {
	clientID, err := normalizeClientID(clientID)
	if err != nil {
		return err
	}

	if _, err := s.oidcClientRepo.GetByClientID(ctx, clientID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOIDCClientNotFound
		}
		return fmt.Errorf("get oidc client for delete: %w", err)
	}

	if err := s.oidcClientRepo.Delete(ctx, clientID); err != nil {
		return fmt.Errorf("delete oidc client: %w", err)
	}
	return nil
}

func (s *oidcClientService) RotateSecret(ctx context.Context, clientID string) (string, error) {
	clientID, err := normalizeClientID(clientID)
	if err != nil {
		return "", err
	}

	client, err := s.oidcClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrOIDCClientNotFound
		}
		return "", fmt.Errorf("get oidc client for rotate: %w", err)
	}

	secret, err := crypto.GenerateClientSecret()
	if err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}

	client.ClientSecret = secret
	if err := s.oidcClientRepo.Update(ctx, client); err != nil {
		return "", fmt.Errorf("update oidc client secret: %w", err)
	}

	return secret, nil
}

func normalizeClientID(clientID string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", fmt.Errorf("%w: client_id is required", ErrOIDCClientInvalid)
	}
	if strings.ContainsAny(clientID, " \t\r\n") {
		return "", fmt.Errorf("%w: client_id must not contain spaces", ErrOIDCClientInvalid)
	}
	return clientID, nil
}

func normalizeClientName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: name is required", ErrOIDCClientInvalid)
	}
	return name, nil
}

func normalizeRedirectURIs(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	normalized := make([]string, 0, len(raw))

	for _, uri := range raw {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		if _, ok := seen[uri]; ok {
			continue
		}

		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme == "" {
			return nil, fmt.Errorf("%w: invalid redirect uri: %s", ErrOIDCClientInvalid, uri)
		}
		if parsed.Fragment != "" {
			return nil, fmt.Errorf("%w: redirect uri must not contain fragment: %s", ErrOIDCClientInvalid, uri)
		}
		if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "" {
			return nil, fmt.Errorf("%w: redirect uri host is required for %s", ErrOIDCClientInvalid, parsed.Scheme)
		}

		seen[uri] = struct{}{}
		normalized = append(normalized, uri)
	}

	if len(normalized) == 0 {
		return nil, fmt.Errorf("%w: redirect_uris is required", ErrOIDCClientInvalid)
	}
	return normalized, nil
}

func normalizeScopes(raw []string, allowDefault bool) ([]string, error) {
	if len(raw) == 0 {
		if allowDefault {
			return append([]string(nil), defaultOIDCScopes...), nil
		}
		return nil, fmt.Errorf("%w: allowed_scopes is required", ErrOIDCClientInvalid)
	}

	seen := make(map[string]struct{}, len(raw))
	normalized := make([]string, 0, len(raw))
	hasOpenID := false

	for _, scope := range raw {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if strings.ContainsAny(scope, " \t\r\n") {
			return nil, fmt.Errorf("%w: invalid scope value: %s", ErrOIDCClientInvalid, scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
		if scope == "openid" {
			hasOpenID = true
		}
	}

	if len(normalized) == 0 {
		return nil, fmt.Errorf("%w: allowed_scopes is required", ErrOIDCClientInvalid)
	}
	if !hasOpenID {
		return nil, fmt.Errorf("%w: allowed_scopes must include openid", ErrOIDCClientInvalid)
	}
	return normalized, nil
}

var _ OIDCClientService = (*oidcClientService)(nil)
