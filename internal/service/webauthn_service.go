package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
)

const webauthnSessionTTL = 5 * time.Minute

type WebAuthnService interface {
	BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error)
	FinishRegistration(ctx context.Context, userID uuid.UUID, sessionID string, r *http.Request) error
	BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*TokenSet, error)
}

type webAuthnService struct {
	wa           *webauthn.WebAuthn
	userRepo     repository.UserRepository
	identityRepo repository.IdentityRepository
	stateStore   repository.StateStore
	authService  AuthService
}

func NewWebAuthnService(
	cfg config.WebAuthnConfig,
	userRepo repository.UserRepository,
	identityRepo repository.IdentityRepository,
	stateStore repository.StateStore,
	authService AuthService,
) (WebAuthnService, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	return &webAuthnService{
		wa:           wa,
		userRepo:     userRepo,
		identityRepo: identityRepo,
		stateStore:   stateStore,
		authService:  authService,
	}, nil
}

func (s *webAuthnService) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, "", ErrUserNotFound
	}

	identities, err := s.identityRepo.ListByUserID(ctx, user.ID)
	if err != nil {
		return nil, "", fmt.Errorf("list identities: %w", err)
	}

	waUser := newWebAuthnUser(user.ID, identities)

	creation, session, err := s.wa.BeginRegistration(
		waUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}

	sessionID := uuid.New().String()
	sessionData, _ := json.Marshal(session)
	if err := s.stateStore.Set(ctx, "webauthn_reg:"+sessionID, sessionData, webauthnSessionTTL); err != nil {
		return nil, "", fmt.Errorf("store session: %w", err)
	}

	return creation, sessionID, nil
}

func (s *webAuthnService) FinishRegistration(ctx context.Context, userID uuid.UUID, sessionID string, r *http.Request) error {
	// Retrieve session
	sessionData, err := s.stateStore.Get(ctx, "webauthn_reg:"+sessionID)
	if err != nil || sessionData == nil {
		return fmt.Errorf("session not found or expired")
	}
	_ = s.stateStore.Delete(ctx, "webauthn_reg:"+sessionID)

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	// Load user and identities
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}
	identities, err := s.identityRepo.ListByUserID(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}
	waUser := newWebAuthnUser(user.ID, identities)

	// Verify attestation
	credential, err := s.wa.FinishRegistration(waUser, session, r)
	if err != nil {
		return fmt.Errorf("finish registration: %w", err)
	}

	// Store credential as identity
	credIdentifier := base64.RawURLEncoding.EncodeToString(credential.ID)

	identity := &model.UserIdentity{
		UserID:         userID,
		IdentityType:   model.IdentityTypePasskey,
		Identifier:     credIdentifier,
		CredentialData: credentialToData(credential),
	}
	return s.identityRepo.Create(ctx, identity)
}

func (s *webAuthnService) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("begin discoverable login: %w", err)
	}

	sessionID := uuid.New().String()
	sessionData, _ := json.Marshal(session)
	if err := s.stateStore.Set(ctx, "webauthn_login:"+sessionID, sessionData, webauthnSessionTTL); err != nil {
		return nil, "", fmt.Errorf("store session: %w", err)
	}

	return assertion, sessionID, nil
}

func (s *webAuthnService) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*TokenSet, error) {
	// Retrieve session
	sessionData, err := s.stateStore.Get(ctx, "webauthn_login:"+sessionID)
	if err != nil || sessionData == nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	_ = s.stateStore.Delete(ctx, "webauthn_login:"+sessionID)

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	// Discoverable user handler: look up user by userHandle (= user UUID bytes)
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, fmt.Errorf("invalid user handle")
		}
		identities, err := s.identityRepo.ListByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return newWebAuthnUser(userID, identities), nil
	}

	waUser, credential, err := s.wa.FinishPasskeyLogin(handler, session, r)
	if err != nil {
		return nil, fmt.Errorf("finish passkey login: %w", err)
	}

	// Update sign count
	userID, err := uuid.FromBytes(waUser.WebAuthnID())
	if err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}

	credIdentifier := base64.RawURLEncoding.EncodeToString(credential.ID)
	existingIdentity, err := s.identityRepo.GetByTypeAndIdentifier(ctx, model.IdentityTypePasskey, credIdentifier)
	if err == nil {
		existingIdentity.CredentialData = credentialToData(credential)
		_ = s.identityRepo.Update(ctx, existingIdentity)
	}

	// Check user status
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserDisabled
	}

	// Issue tokens
	if as, ok := s.authService.(*authService); ok {
		return as.issueTokenSet(ctx, user.ID)
	}
	return nil, fmt.Errorf("internal error: cannot issue tokens")
}
