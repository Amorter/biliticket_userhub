package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/op"

	oidcmod "biliticket/userhub/internal/oidc"
	"biliticket/userhub/pkg/response"
)

// OIDCHandler handles OIDC-related endpoints that are not part of the standard OIDC provider.
type OIDCHandler struct {
	storage  *oidcmod.Storage
	provider op.OpenIDProvider
}

func NewOIDCHandler(storage *oidcmod.Storage, provider op.OpenIDProvider) *OIDCHandler {
	return &OIDCHandler{storage: storage, provider: provider}
}

type CompleteAuthRequest struct {
	AuthRequestID string `json:"auth_request_id" binding:"required"`
}

// CompleteLogin marks an OIDC auth request as done for the logged-in user,
// then returns the callback URL for the frontend to redirect to.
func (h *OIDCHandler) CompleteLogin(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	var req CompleteAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Mark auth request as done with user ID
	if err := h.storage.CompleteAuthRequest(c.Request.Context(), req.AuthRequestID, userID.String()); err != nil {
		response.BadRequest(c, "invalid or expired auth request")
		return
	}

	// Build the callback URL
	callbackURL := op.AuthCallbackURL(h.provider)(c.Request.Context(), req.AuthRequestID)

	response.Success(c, gin.H{"callback_url": callbackURL})
}

// MountOIDCProvider mounts the zitadel/oidc provider as a handler on gin.
func MountOIDCProvider(r *gin.Engine, provider op.OpenIDProvider) {
	r.Any("/oidc/*path", gin.WrapH(http.StripPrefix("/oidc", provider)))
}
