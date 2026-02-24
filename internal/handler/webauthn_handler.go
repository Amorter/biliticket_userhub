package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type WebAuthnHandler struct {
	webAuthnService service.WebAuthnService
}

func NewWebAuthnHandler(webAuthnService service.WebAuthnService) *WebAuthnHandler {
	return &WebAuthnHandler{webAuthnService: webAuthnService}
}

// BeginRegistration starts passkey registration for the authenticated user.
func (h *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	creation, sessionID, err := h.webAuthnService.BeginRegistration(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to begin passkey registration")
		return
	}

	response.Success(c, gin.H{
		"options":    creation,
		"session_id": sessionID,
	})
}

type FinishRegistrationRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// FinishRegistration completes passkey registration.
// The WebAuthn attestation response is read from the HTTP request body by the library.
// We pass session_id as a query param and the attestation as the body.
func (h *WebAuthnHandler) FinishRegistration(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	sessionID := c.Query("session_id")
	if sessionID == "" {
		response.BadRequest(c, "missing session_id")
		return
	}

	if err := h.webAuthnService.FinishRegistration(c.Request.Context(), userID, sessionID, c.Request); err != nil {
		response.BadRequest(c, "passkey registration failed: "+err.Error())
		return
	}

	response.Success(c, nil)
}

// BeginLogin starts passkey discoverable login.
func (h *WebAuthnHandler) BeginLogin(c *gin.Context) {
	assertion, sessionID, err := h.webAuthnService.BeginLogin(c.Request.Context())
	if err != nil {
		response.InternalError(c, "failed to begin passkey login")
		return
	}

	response.Success(c, gin.H{
		"options":    assertion,
		"session_id": sessionID,
	})
}

// FinishLogin completes passkey login.
func (h *WebAuthnHandler) FinishLogin(c *gin.Context) {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		response.BadRequest(c, "missing session_id")
		return
	}

	tokenSet, err := h.webAuthnService.FinishLogin(c.Request.Context(), sessionID, c.Request)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserDisabled):
			response.Error(c, 403, 403, "user is disabled")
		case errors.Is(err, service.ErrProfileIncomplete):
			response.Error(c, 403, 403, "user profile incomplete, username and display_name are required")
		case errors.Is(err, service.ErrEmailNotVerified):
			response.Error(c, 403, 403, "email is not verified")
		default:
			response.Unauthorized(c, "passkey login failed: "+err.Error())
		}
		return
	}

	response.Success(c, tokenSet)
}
