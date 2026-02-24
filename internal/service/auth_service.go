package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/pkg/crypto"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

const (
	emailVerifyStateKeyPrefix   = "email_verify:"
	emailVerifyPurposeRegister  = "register"
	emailVerifyPurposeUser      = "verify_user"
	defaultEmailVerifyTokenTTL  = 30 * time.Minute
	defaultEmailVerifyTokenSize = 32
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,64}$`)

// TokenSet represents a set of tokens returned after authentication.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type RegisterResult struct {
	User                      *model.User `json:"user"`
	EmailVerificationRequired bool        `json:"email_verification_required"`
	EmailVerificationSent     bool        `json:"email_verification_sent"`
}

type AuthService interface {
	Register(
		ctx context.Context,
		identityType model.IdentityType,
		identifier string,
		credentialData model.CredentialData,
		username string,
		displayName string,
		email string,
		emailVerificationToken string,
		inviteCode string,
	) (*RegisterResult, error)
	Login(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData) (*TokenSet, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error)
	Logout(ctx context.Context, refreshToken string) error
	RequestRegistrationEmailVerification(ctx context.Context, email string) error
	VerifyEmail(ctx context.Context, token string) error
	ResendEmailVerification(ctx context.Context, identifier string) error
}

type authService struct {
	userRepo       repository.UserRepository
	identityRepo   repository.IdentityRepository
	inviteRepo     repository.InviteCodeRepository
	stateStore     repository.StateStore
	jwtManager     *jwtpkg.Manager
	inviteEnabled  bool
	emailVerifyCfg config.EmailVerificationConfig
	mailSender     MailSender
}

func NewAuthService(
	userRepo repository.UserRepository,
	identityRepo repository.IdentityRepository,
	inviteRepo repository.InviteCodeRepository,
	stateStore repository.StateStore,
	jwtManager *jwtpkg.Manager,
	inviteEnabled bool,
	emailVerifyCfg config.EmailVerificationConfig,
	mailSender MailSender,
) AuthService {
	return &authService{
		userRepo:       userRepo,
		identityRepo:   identityRepo,
		inviteRepo:     inviteRepo,
		stateStore:     stateStore,
		jwtManager:     jwtManager,
		inviteEnabled:  inviteEnabled,
		emailVerifyCfg: normalizeEmailVerifyConfig(emailVerifyCfg),
		mailSender:     mailSender,
	}
}

type emailVerifyPayload struct {
	Purpose string `json:"purpose"` // register | verify_user
	UserID  string `json:"user_id,omitempty"`
	Email   string `json:"email"`
}

func (s *authService) Register(
	ctx context.Context,
	identityType model.IdentityType,
	identifier string,
	credentialData model.CredentialData,
	username string,
	displayName string,
	email string,
	emailVerificationToken string,
	inviteCode string,
) (*RegisterResult, error) {
	// 1. Validate invite code if enabled.
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

	identifier = normalizeIdentifier(identityType, identifier)
	if identifier == "" {
		return nil, ErrInvalidProfile
	}

	normalizedUsername, err := normalizeUsername(username)
	if err != nil {
		return nil, err
	}

	normalizedDisplayName := normalizeDisplayName(displayName, normalizedUsername)
	if normalizedDisplayName == "" {
		return nil, ErrInvalidProfile
	}

	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}
	if identityType == model.IdentityTypePassword && normalizedEmail == "" {
		if normalizedFromIdentifier, nerr := normalizeEmail(identifier); nerr == nil {
			normalizedEmail = normalizedFromIdentifier
		}
	}
	if identityType == model.IdentityTypePassword && normalizedEmail == "" {
		return nil, ErrEmailRequired
	}

	preVerified := false
	regVerifyStateKey := ""
	if s.emailVerifyCfg.Enabled && normalizedEmail != "" {
		trimmedToken := strings.TrimSpace(emailVerificationToken)
		if trimmedToken != "" {
			stateKey, err := s.validateRegistrationEmailToken(ctx, normalizedEmail, trimmedToken)
			if err != nil {
				return nil, err
			}
			preVerified = true
			regVerifyStateKey = stateKey
		} else if s.emailVerifyCfg.RequireVerifiedForRegister {
			return nil, ErrEmailVerifyTokenRequired
		}
	}

	// 2. Check identity uniqueness.
	_, err = s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, identifier)
	if err == nil {
		return nil, ErrIdentityAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check identity: %w", err)
	}

	// 3. Check username uniqueness.
	_, err = s.userRepo.GetByUsername(ctx, normalizedUsername)
	if err == nil {
		return nil, ErrUsernameAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}

	// 4. Check email uniqueness.
	if normalizedEmail != "" {
		_, err = s.userRepo.GetByEmail(ctx, normalizedEmail)
		if err == nil {
			return nil, ErrEmailAlreadyExists
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to check email: %w", err)
		}
	}

	// 5. Process credentials.
	processed, err := processCredentialData(identityType, credentialData)
	if err != nil {
		return nil, err
	}

	// 6. Create user.
	var verifiedAt *time.Time
	if preVerified {
		now := time.Now().UTC()
		verifiedAt = &now
	}
	user := &model.User{
		Username:        normalizedUsername,
		DisplayName:     normalizedDisplayName,
		Email:           normalizedEmail,
		EmailVerifiedAt: verifiedAt,
		Status:          model.UserStatusActive,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// 7. Create identity.
	identity := &model.UserIdentity{
		UserID:         user.ID,
		IdentityType:   identityType,
		Identifier:     identifier,
		CredentialData: processed,
	}
	if err := s.identityRepo.Create(ctx, identity); err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// 8. Increment invite code usage.
	if s.inviteEnabled && inviteCode != "" {
		if err := s.inviteRepo.IncrementUsedCount(ctx, inviteCode); err != nil {
			return nil, fmt.Errorf("failed to increment invite code: %w", err)
		}
	}
	if preVerified && regVerifyStateKey != "" {
		_ = s.stateStore.Delete(ctx, regVerifyStateKey)
	}

	result := &RegisterResult{
		User:                      user,
		EmailVerificationRequired: s.emailVerifyCfg.Enabled && normalizedEmail != "" && !preVerified,
		EmailVerificationSent:     false,
	}
	if result.EmailVerificationRequired {
		if err := s.sendEmailVerification(ctx, user); err == nil {
			result.EmailVerificationSent = true
		}
	}

	return result, nil
}

func (s *authService) RequestRegistrationEmailVerification(ctx context.Context, email string) error {
	if !s.emailVerifyCfg.Enabled {
		return ErrEmailVerifyDisabled
	}
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	if normalizedEmail == "" {
		return ErrEmailRequired
	}
	if s.mailSender == nil {
		return fmt.Errorf("mail sender is not configured")
	}
	if strings.TrimSpace(s.emailVerifyCfg.VerifyURLTemplate) == "" {
		return fmt.Errorf("email verification verify_url_template is required")
	}

	token, stateKey, err := s.createEmailVerificationToken(ctx, emailVerifyPayload{
		Purpose: emailVerifyPurposeRegister,
		Email:   normalizedEmail,
	})
	if err != nil {
		return err
	}

	verifyURL := buildVerifyURL(s.emailVerifyCfg.VerifyURLTemplate, token)
	subject := "请完成注册前邮箱验证"
	body := fmt.Sprintf(
		"你好：\n\n请点击以下链接完成邮箱验证后再注册：\n%s\n\n该链接将在 %s 后失效。\n如果不是你本人操作，请忽略此邮件。",
		verifyURL,
		s.emailVerifyCfg.TokenTTL.String(),
	)
	if err := s.mailSender.Send(ctx, normalizedEmail, subject, body); err != nil {
		_ = s.stateStore.Delete(ctx, stateKey)
		return fmt.Errorf("send registration verify email: %w", err)
	}
	return nil
}

func (s *authService) Login(ctx context.Context, identityType model.IdentityType, identifier string, credentialData model.CredentialData) (*TokenSet, error) {
	identifier = normalizeIdentifier(identityType, identifier)

	// 1. Find identity.
	identity, err := s.identityRepo.GetByTypeAndIdentifier(ctx, identityType, identifier)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find identity: %w", err)
	}

	// 2. Load user.
	user, err := s.userRepo.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// 3. Verify credentials.
	switch identityType {
	case model.IdentityTypePassword:
		password, ok := credentialData["password"].(string)
		if !ok || strings.TrimSpace(password) == "" {
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

	// 4. Check login policy.
	if err := s.ensureUserCanLogin(user); err != nil {
		return nil, err
	}

	// 5. Issue tokens.
	return s.issueTokenSet(ctx, user.ID)
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	// 1. Validate refresh token.
	claims, err := s.jwtManager.Validate(refreshToken)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}
	if claims.TokenType != jwtpkg.TokenTypeRefresh {
		return nil, ErrRefreshTokenInvalid
	}

	// 2. Check JTI in StateStore.
	stateKey := "refresh_token:" + claims.ID
	value, err := s.stateStore.Get(ctx, stateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check refresh token state: %w", err)
	}
	if value == nil {
		return nil, ErrRefreshTokenInvalid
	}

	// 3. Check user login policy.
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if err := s.ensureUserCanLogin(user); err != nil {
		return nil, err
	}

	// 4. Token rotation: delete old JTI.
	_ = s.stateStore.Delete(ctx, stateKey)

	// 5. Issue new token set.
	return s.issueTokenSet(ctx, user.ID)
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	// 1. Validate refresh token.
	claims, err := s.jwtManager.Validate(refreshToken)
	if err != nil {
		return ErrRefreshTokenInvalid
	}
	if claims.TokenType != jwtpkg.TokenTypeRefresh {
		return ErrRefreshTokenInvalid
	}

	// 2. Delete JTI from StateStore.
	stateKey := "refresh_token:" + claims.ID
	return s.stateStore.Delete(ctx, stateKey)
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	if !s.emailVerifyCfg.Enabled {
		return ErrEmailVerifyDisabled
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return ErrEmailVerifyToken
	}

	stateKey := emailVerifyStateKeyPrefix + token
	raw, err := s.stateStore.Get(ctx, stateKey)
	if err != nil {
		return fmt.Errorf("failed to load verification state: %w", err)
	}
	if raw == nil {
		return ErrEmailVerifyToken
	}
	_ = s.stateStore.Delete(ctx, stateKey)

	var payload emailVerifyPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ErrEmailVerifyToken
	}
	if payload.Purpose != emailVerifyPurposeUser {
		return ErrEmailVerifyToken
	}

	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		return ErrEmailVerifyToken
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrEmailVerifyToken
		}
		return fmt.Errorf("failed to load user: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(user.Email), strings.TrimSpace(payload.Email)) {
		return ErrEmailVerifyToken
	}
	if user.EmailVerifiedAt != nil {
		return nil
	}

	now := time.Now().UTC()
	user.EmailVerifiedAt = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user verification: %w", err)
	}
	return nil
}

func (s *authService) ResendEmailVerification(ctx context.Context, identifier string) error {
	if !s.emailVerifyCfg.Enabled {
		return ErrEmailVerifyDisabled
	}

	identifier = normalizeIdentifier(model.IdentityTypePassword, identifier)
	if identifier == "" {
		return ErrInvalidProfile
	}

	identity, err := s.identityRepo.GetByTypeAndIdentifier(ctx, model.IdentityTypePassword, identifier)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Avoid user enumeration.
			return nil
		}
		return fmt.Errorf("failed to look up password identity: %w", err)
	}

	user, err := s.userRepo.GetByID(ctx, identity.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("failed to load user: %w", err)
	}
	if strings.TrimSpace(user.Email) == "" || user.EmailVerifiedAt != nil {
		return nil
	}

	return s.sendEmailVerification(ctx, user)
}

// issueTokenSet generates access, refresh, and ID tokens and stores refresh JTI in StateStore.
func (s *authService) issueTokenSet(ctx context.Context, userID uuid.UUID) (*TokenSet, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to load user for token issue: %w", err)
	}
	if err := s.ensureUserCanLogin(user); err != nil {
		return nil, err
	}

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

	// Store refresh token JTI in StateStore.
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

func (s *authService) ensureUserCanLogin(user *model.User) error {
	if user.Status != model.UserStatusActive {
		return ErrUserDisabled
	}
	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.DisplayName) == "" {
		return ErrProfileIncomplete
	}
	if s.emailVerifyCfg.Enabled &&
		s.emailVerifyCfg.RequireVerifiedForLogin &&
		strings.TrimSpace(user.Email) != "" &&
		user.EmailVerifiedAt == nil {
		return ErrEmailNotVerified
	}
	return nil
}

func (s *authService) sendEmailVerification(ctx context.Context, user *model.User) error {
	if !s.emailVerifyCfg.Enabled || strings.TrimSpace(user.Email) == "" {
		return nil
	}
	if s.mailSender == nil {
		return fmt.Errorf("mail sender is not configured")
	}
	if strings.TrimSpace(s.emailVerifyCfg.VerifyURLTemplate) == "" {
		return fmt.Errorf("email verification verify_url_template is required")
	}

	token, stateKey, err := s.createEmailVerificationToken(ctx, emailVerifyPayload{
		Purpose: emailVerifyPurposeUser,
		UserID:  user.ID.String(),
		Email:   user.Email,
	})
	if err != nil {
		return err
	}

	verifyURL := buildVerifyURL(s.emailVerifyCfg.VerifyURLTemplate, token)
	subject := "请验证你的邮箱地址"
	body := fmt.Sprintf(
		"你好，%s：\n\n请点击以下链接完成邮箱验证：\n%s\n\n该链接将在 %s 后失效。\n如果不是你本人操作，请忽略此邮件。",
		user.DisplayName,
		verifyURL,
		s.emailVerifyCfg.TokenTTL.String(),
	)
	if err := s.mailSender.Send(ctx, user.Email, subject, body); err != nil {
		_ = s.stateStore.Delete(ctx, stateKey)
		return fmt.Errorf("send verify email: %w", err)
	}
	return nil
}

func (s *authService) validateRegistrationEmailToken(ctx context.Context, email string, token string) (string, error) {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(token) == "" {
		return "", ErrEmailVerifyToken
	}
	stateKey := emailVerifyStateKeyPrefix + token
	raw, err := s.stateStore.Get(ctx, stateKey)
	if err != nil {
		return "", fmt.Errorf("failed to load verification state: %w", err)
	}
	if raw == nil {
		return "", ErrEmailVerifyToken
	}

	var payload emailVerifyPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", ErrEmailVerifyToken
	}
	if payload.Purpose != emailVerifyPurposeRegister {
		return "", ErrEmailVerifyToken
	}
	if !strings.EqualFold(strings.TrimSpace(payload.Email), strings.TrimSpace(email)) {
		return "", ErrEmailVerifyToken
	}
	return stateKey, nil
}

func (s *authService) createEmailVerificationToken(ctx context.Context, payload emailVerifyPayload) (string, string, error) {
	token, err := crypto.GenerateRandomString(s.emailVerifyCfg.TokenSizeBytes)
	if err != nil {
		return "", "", fmt.Errorf("generate verify token: %w", err)
	}
	data, _ := json.Marshal(payload)
	stateKey := emailVerifyStateKeyPrefix + token
	if err := s.stateStore.Set(ctx, stateKey, data, s.emailVerifyCfg.TokenTTL); err != nil {
		return "", "", fmt.Errorf("store verify token: %w", err)
	}
	return token, stateKey, nil
}

func normalizeIdentifier(identityType model.IdentityType, identifier string) string {
	_ = identityType
	return strings.TrimSpace(identifier)
}

func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", ErrInvalidProfile
	}
	if !usernamePattern.MatchString(username) {
		return "", ErrInvalidProfile
	}
	return username, nil
}

func normalizeDisplayName(displayName string, username string) string {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return username
	}
	return displayName
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", nil
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", ErrInvalidProfile
	}
	if !strings.EqualFold(addr.Address, email) {
		return "", ErrInvalidProfile
	}
	return email, nil
}

func buildVerifyURL(template string, token string) string {
	if strings.Contains(template, "{{TOKEN}}") {
		return strings.ReplaceAll(template, "{{TOKEN}}", url.QueryEscape(token))
	}
	if strings.Contains(template, "?") {
		return template + "&token=" + url.QueryEscape(token)
	}
	return template + "?token=" + url.QueryEscape(token)
}

func normalizeEmailVerifyConfig(cfg config.EmailVerificationConfig) config.EmailVerificationConfig {
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultEmailVerifyTokenTTL
	}
	if cfg.TokenSizeBytes <= 0 {
		cfg.TokenSizeBytes = defaultEmailVerifyTokenSize
	}
	return cfg
}

// processCredentialData processes raw credentials based on identity type.
func processCredentialData(identityType model.IdentityType, raw model.CredentialData) (model.CredentialData, error) {
	switch identityType {
	case model.IdentityTypePassword:
		password, ok := raw["password"].(string)
		if !ok || strings.TrimSpace(password) == "" {
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

// ensure authService implements AuthService.
var _ AuthService = (*authService)(nil)
