package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type RegisterRequest struct {
	IdentityType           string                 `json:"identity_type" binding:"required"`
	Identifier             string                 `json:"identifier" binding:"required"`
	CredentialData         map[string]interface{} `json:"credential_data" binding:"required"`
	Username               string                 `json:"username" binding:"required"`
	DisplayName            string                 `json:"display_name"`
	Email                  string                 `json:"email"`
	EmailVerificationToken string                 `json:"email_verification_token"`
	InviteCode             string                 `json:"invite_code"`
}

type LoginRequest struct {
	IdentityType   string                 `json:"identity_type" binding:"required"`
	Identifier     string                 `json:"identifier" binding:"required"`
	CredentialData map[string]interface{} `json:"credential_data" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RequestRegistrationVerifyEmailRequest struct {
	Email string `json:"email" binding:"required"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type ResendVerifyEmailRequest struct {
	Identifier string `json:"identifier" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	identityType := model.IdentityType(req.IdentityType)
	if !isValidIdentityType(identityType) {
		response.BadRequest(c, "unsupported identity type")
		return
	}

	result, err := h.authService.Register(
		c.Request.Context(),
		identityType,
		req.Identifier,
		model.CredentialData(req.CredentialData),
		req.Username,
		req.DisplayName,
		req.Email,
		req.EmailVerificationToken,
		req.InviteCode,
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIdentityAlreadyExists):
			response.Error(c, 409, 409, err.Error())
		case errors.Is(err, service.ErrUsernameAlreadyExists),
			errors.Is(err, service.ErrEmailAlreadyExists):
			response.Error(c, 409, 409, err.Error())
		case errors.Is(err, service.ErrInviteCodeRequired),
			errors.Is(err, service.ErrInviteCodeInvalid),
			errors.Is(err, service.ErrInviteCodeExhausted),
			errors.Is(err, service.ErrInvalidProfile),
			errors.Is(err, service.ErrEmailRequired),
			errors.Is(err, service.ErrEmailVerifyToken),
			errors.Is(err, service.ErrEmailVerifyTokenRequired):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "registration failed")
		}
		return
	}

	response.Success(c, gin.H{
		"user_id":                     result.User.ID,
		"email_verification_required": result.EmailVerificationRequired,
		"email_verification_sent":     result.EmailVerificationSent,
	})
}

func (h *AuthHandler) RequestRegistrationVerifyEmail(c *gin.Context) {
	var req RequestRegistrationVerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	if err := h.authService.RequestRegistrationEmailVerification(c.Request.Context(), req.Email); err != nil {
		switch {
		case errors.Is(err, service.ErrEmailVerifyDisabled):
			response.BadRequest(c, err.Error())
		case errors.Is(err, service.ErrInvalidProfile),
			errors.Is(err, service.ErrEmailRequired):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "failed to send registration verification email")
		}
		return
	}

	response.Success(c, gin.H{
		"message": "verification email sent",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	identityType := model.IdentityType(req.IdentityType)
	if !isValidIdentityType(identityType) {
		response.BadRequest(c, "unsupported identity type")
		return
	}

	tokenSet, err := h.authService.Login(
		c.Request.Context(),
		identityType,
		req.Identifier,
		model.CredentialData(req.CredentialData),
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			response.Unauthorized(c, "invalid credentials")
		case errors.Is(err, service.ErrUserDisabled):
			response.Error(c, 403, 403, "user is disabled")
		case errors.Is(err, service.ErrProfileIncomplete):
			response.Error(c, 403, 403, "user profile incomplete, username and display_name are required")
		case errors.Is(err, service.ErrEmailNotVerified):
			response.Error(c, 403, 403, "email is not verified")
		case errors.Is(err, service.ErrUnsupportedIdentity):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "login failed")
		}
		return
	}

	response.Success(c, tokenSet)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	tokenSet, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRefreshTokenInvalid):
			response.Unauthorized(c, "invalid refresh token")
		case errors.Is(err, service.ErrUserDisabled):
			response.Error(c, 403, 403, "user is disabled")
		case errors.Is(err, service.ErrProfileIncomplete):
			response.Error(c, 403, 403, "user profile incomplete, username and display_name are required")
		case errors.Is(err, service.ErrEmailNotVerified):
			response.Error(c, 403, 403, "email is not verified")
		default:
			response.InternalError(c, "token refresh failed")
		}
		return
	}

	response.Success(c, tokenSet)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	if err := h.authService.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		response.InternalError(c, "logout failed")
		return
	}

	response.Success(c, nil)
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	if err := h.authService.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		switch {
		case errors.Is(err, service.ErrEmailVerifyDisabled):
			response.BadRequest(c, err.Error())
		case errors.Is(err, service.ErrEmailVerifyToken):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "email verification failed")
		}
		return
	}

	response.Success(c, gin.H{"verified": true})
}

func (h *AuthHandler) ResendVerifyEmail(c *gin.Context) {
	var req ResendVerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	if err := h.authService.ResendEmailVerification(c.Request.Context(), req.Identifier); err != nil {
		switch {
		case errors.Is(err, service.ErrEmailVerifyDisabled):
			response.BadRequest(c, err.Error())
		case errors.Is(err, service.ErrInvalidProfile):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "failed to resend verification email")
		}
		return
	}

	response.Success(c, gin.H{
		"message": "if the account exists and email is unverified, a verification email has been sent",
	})
}

func isValidIdentityType(t model.IdentityType) bool {
	switch t {
	case model.IdentityTypePassword,
		model.IdentityTypeGitHub,
		model.IdentityTypeGoogle,
		model.IdentityTypePasskey:
		return true
	}
	return false
}
