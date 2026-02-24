package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gorm.io/gorm"

	"biliticket/userhub/internal/repository"
	"biliticket/userhub/pkg/crypto"
)

const (
	authReqTTL  = 10 * time.Minute
	authCodeTTL = 10 * time.Minute
)

// tokenInfo stores metadata about issued tokens in StateStore.
type tokenInfo struct {
	TokenID   string    `json:"token_id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	Audience  []string  `json:"audience"`
	AMR       []string  `json:"amr"`
	AuthTime  time.Time `json:"auth_time"`
	ExpiresAt time.Time `json:"expires_at"`
}

// refreshTokenInfo stores metadata about refresh tokens.
type refreshTokenInfo struct {
	tokenInfo
	RefreshTokenID string `json:"refresh_token_id"`
}

// Storage implements op.Storage by bridging our repository layer.
type Storage struct {
	oidcClientRepo repository.OIDCClientRepository
	userRepo       repository.UserRepository
	identityRepo   repository.IdentityRepository
	stateStore     repository.StateStore
	keyPair        *KeyPair
	loginURL       string
	accessTTL      time.Duration
	refreshTTL     time.Duration
}

func NewStorage(
	oidcClientRepo repository.OIDCClientRepository,
	userRepo repository.UserRepository,
	identityRepo repository.IdentityRepository,
	stateStore repository.StateStore,
	keyPair *KeyPair,
	loginURL string,
	accessTTL, refreshTTL time.Duration,
) *Storage {
	return &Storage{
		oidcClientRepo: oidcClientRepo,
		userRepo:       userRepo,
		identityRepo:   identityRepo,
		stateStore:     stateStore,
		keyPair:        keyPair,
		loginURL:       loginURL,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
	}
}

// --- AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, oidcReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id := uuid.New().String()
	req := authRequestFromOIDC(oidcReq, id)
	if userID != "" {
		req.UserID = userID
	}

	data, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal auth request: %w", err)
	}
	if err := s.stateStore.Set(ctx, "oidc_auth_req:"+id, data, authReqTTL); err != nil {
		return nil, fmt.Errorf("store auth request: %w", err)
	}
	return req, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	data, err := s.stateStore.Get(ctx, "oidc_auth_req:"+id)
	if err != nil {
		return nil, fmt.Errorf("get auth request: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("auth request not found")
	}
	return UnmarshalAuthRequest(data)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// Look up auth request ID from code
	reqIDBytes, err := s.stateStore.Get(ctx, "oidc_code:"+code)
	if err != nil {
		return nil, fmt.Errorf("get auth code: %w", err)
	}
	if reqIDBytes == nil {
		return nil, fmt.Errorf("auth code not found")
	}
	return s.AuthRequestByID(ctx, string(reqIDBytes))
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.stateStore.Set(ctx, "oidc_code:"+code, []byte(id), authCodeTTL)
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.stateStore.Delete(ctx, "oidc_auth_req:"+id)
}

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expiration := time.Now().Add(s.accessTTL)

	info := tokenInfo{
		TokenID:   tokenID,
		UserID:    request.GetSubject(),
		Scopes:    request.GetScopes(),
		Audience:  request.GetAudience(),
		ExpiresAt: expiration,
	}

	// Extract additional fields if available from AuthRequest
	if authReq, ok := request.(op.AuthRequest); ok {
		info.ClientID = authReq.GetClientID()
		info.AMR = authReq.GetAMR()
		info.AuthTime = authReq.GetAuthTime()
	}

	data, _ := json.Marshal(info)
	if err := s.stateStore.Set(ctx, "oidc_access:"+tokenID, data, s.accessTTL); err != nil {
		return "", time.Time{}, err
	}

	return tokenID, expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	// Delete old refresh token if rotating
	if currentRefreshToken != "" {
		_ = s.stateStore.Delete(ctx, "oidc_refresh:"+currentRefreshToken)
	}

	// Create access token
	tokenID, expiration, err := s.CreateAccessToken(ctx, request)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Create refresh token
	refreshToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", "", time.Time{}, err
	}

	rtInfo := refreshTokenInfo{
		tokenInfo: tokenInfo{
			TokenID:  tokenID,
			UserID:   request.GetSubject(),
			Scopes:   request.GetScopes(),
			Audience: request.GetAudience(),
		},
		RefreshTokenID: refreshToken,
	}
	if authReq, ok := request.(op.AuthRequest); ok {
		rtInfo.ClientID = authReq.GetClientID()
		rtInfo.AMR = authReq.GetAMR()
		rtInfo.AuthTime = authReq.GetAuthTime()
	}

	data, _ := json.Marshal(rtInfo)
	if err := s.stateStore.Set(ctx, "oidc_refresh:"+refreshToken, data, s.refreshTTL); err != nil {
		return "", "", time.Time{}, err
	}

	return tokenID, refreshToken, expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	data, err := s.stateStore.Get(ctx, "oidc_refresh:"+refreshToken)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("refresh token not found")
	}

	var info refreshTokenInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &refreshTokenReq{info: info}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	// For now, sessions are stateless (JWT-based). No-op.
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	// Try as access token
	if err := s.stateStore.Delete(ctx, "oidc_access:"+tokenOrTokenID); err == nil {
		return nil
	}
	// Try as refresh token
	if err := s.stateStore.Delete(ctx, "oidc_refresh:"+tokenOrTokenID); err == nil {
		return nil
	}
	return nil // RFC 7009: revocation of invalid token is not an error
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	data, err := s.stateStore.Get(ctx, "oidc_refresh:"+token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	if data == nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	var info refreshTokenInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return info.UserID, token, nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.keyPair.SigningKey(), nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{s.keyPair.PublicKey()}, nil
}

// --- OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	client, err := s.oidcClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("client not found: %s", clientID)
		}
		return nil, err
	}
	return NewClient(client, s.loginURL), nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.oidcClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("client not found")
	}
	if client.ClientSecret != clientSecret {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, userID, scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return s.setUserinfo(ctx, userinfo, subject, nil)
}

func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, userID string, scopes []string) error {
	userinfo.Subject = userID

	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil
	}

	user, err := s.userRepo.GetByID(ctx, uid)
	if err == nil && strings.TrimSpace(user.Email) != "" {
		userinfo.Email = user.Email
		userinfo.EmailVerified = oidc.Bool(user.EmailVerifiedAt != nil)
		return nil
	}

	// Backward compatibility: fall back to password identity identifier if user.email is empty.
	identities, err := s.identityRepo.ListByUserID(ctx, uid)
	if err == nil {
		for _, id := range identities {
			if id.IdentityType == "password" {
				userinfo.Email = id.Identifier
				userinfo.EmailVerified = oidc.Bool(false)
				break
			}
		}
	}

	return nil
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	introspection.Active = true
	introspection.Subject = subject
	introspection.ClientID = clientID
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("not supported")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- Health ---

func (s *Storage) Health(ctx context.Context) error {
	return nil
}

// CompleteAuthRequest marks the auth request as done for the given user.
func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	data, err := s.stateStore.Get(ctx, "oidc_auth_req:"+authRequestID)
	if err != nil {
		return fmt.Errorf("get auth request: %w", err)
	}
	if data == nil {
		return fmt.Errorf("auth request not found")
	}

	req, err := UnmarshalAuthRequest(data)
	if err != nil {
		return err
	}

	req.CompleteAuthRequest(userID)

	newData, err := req.Marshal()
	if err != nil {
		return err
	}
	return s.stateStore.Set(ctx, "oidc_auth_req:"+authRequestID, newData, authReqTTL)
}

// --- refreshTokenReq implements op.RefreshTokenRequest ---

type refreshTokenReq struct {
	info   refreshTokenInfo
	scopes []string // mutable scopes
}

func (r *refreshTokenReq) GetAMR() []string       { return r.info.AMR }
func (r *refreshTokenReq) GetAudience() []string  { return r.info.Audience }
func (r *refreshTokenReq) GetAuthTime() time.Time { return r.info.AuthTime }
func (r *refreshTokenReq) GetClientID() string    { return r.info.ClientID }
func (r *refreshTokenReq) GetScopes() []string {
	if r.scopes != nil {
		return r.scopes
	}
	return r.info.Scopes
}
func (r *refreshTokenReq) GetSubject() string               { return r.info.UserID }
func (r *refreshTokenReq) SetCurrentScopes(scopes []string) { r.scopes = scopes }
