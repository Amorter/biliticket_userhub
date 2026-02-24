package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type OAuth2Handler struct {
	oauth2Service service.OAuth2Service
}

func NewOAuth2Handler(oauth2Service service.OAuth2Service) *OAuth2Handler {
	return &OAuth2Handler{oauth2Service: oauth2Service}
}

// Authorize redirects the user to the OAuth2 provider's authorization page.
func (h *OAuth2Handler) Authorize(c *gin.Context) {
	provider := c.Param("provider")

	authURL, err := h.oauth2Service.GetAuthorizationURL(c.Request.Context(), provider)
	if err != nil {
		if errors.Is(err, service.ErrOAuth2ProviderNotConfigured) {
			response.BadRequest(c, "oauth2 provider not configured")
			return
		}
		response.InternalError(c, "failed to generate authorization URL")
		return
	}

	c.Redirect(http.StatusFound, authURL)
}

// Callback handles the OAuth2 provider's callback after authorization.
func (h *OAuth2Handler) Callback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		response.BadRequest(c, "missing code or state")
		return
	}

	tokenSet, err := h.oauth2Service.HandleCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOAuth2InvalidState):
			response.BadRequest(c, "invalid or expired state")
		case errors.Is(err, service.ErrIdentityNotFound):
			response.Error(c, 404, 404, "identity not bound to any account, please register or bind first")
		case errors.Is(err, service.ErrUserDisabled):
			response.Error(c, 403, 403, "user is disabled")
		case errors.Is(err, service.ErrProfileIncomplete):
			response.Error(c, 403, 403, "user profile incomplete, username and display_name are required")
		case errors.Is(err, service.ErrEmailNotVerified):
			response.Error(c, 403, 403, "email is not verified")
		default:
			response.InternalError(c, "oauth2 login failed")
		}
		return
	}

	response.Success(c, tokenSet)
}

// BindAuthorize redirects an authenticated user to OAuth2 provider for identity binding.
func (h *OAuth2Handler) BindAuthorize(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	provider := c.Param("provider")

	authURL, err := h.oauth2Service.GetBindAuthorizationURL(c.Request.Context(), provider, userID)
	if err != nil {
		if errors.Is(err, service.ErrOAuth2ProviderNotConfigured) {
			response.BadRequest(c, "oauth2 provider not configured")
			return
		}
		response.InternalError(c, "failed to generate authorization URL")
		return
	}

	response.Success(c, gin.H{"authorize_url": authURL})
}

// BindCallback handles the callback for OAuth2 identity binding.
func (h *OAuth2Handler) BindCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		response.BadRequest(c, "missing code or state")
		return
	}

	err := h.oauth2Service.HandleBindCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOAuth2InvalidState):
			response.BadRequest(c, "invalid or expired state")
		case errors.Is(err, service.ErrIdentityAlreadyExists):
			response.Error(c, 409, 409, "identity already bound to another account")
		default:
			response.InternalError(c, "oauth2 bind failed")
		}
		return
	}

	response.Success(c, nil)
}
