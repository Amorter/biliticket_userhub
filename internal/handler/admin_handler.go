package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type AdminHandler struct {
	inviteService     service.InviteService
	oidcClientService service.OIDCClientService
}

func NewAdminHandler(inviteService service.InviteService, oidcClientService service.OIDCClientService) *AdminHandler {
	return &AdminHandler{
		inviteService:     inviteService,
		oidcClientService: oidcClientService,
	}
}

type CreateInviteCodeRequest struct {
	MaxUses   int        `json:"max_uses"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateInviteCode creates a new invite code.
func (h *AdminHandler) CreateInviteCode(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	var req CreateInviteCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request body: "+err.Error())
		return
	}

	code, err := h.inviteService.CreateInviteCode(c.Request.Context(), userID, req.MaxUses, req.ExpiresAt)
	if err != nil {
		response.InternalError(c, "failed to create invite code")
		return
	}

	response.Success(c, code)
}

// ListInviteCodes returns all invite codes.
func (h *AdminHandler) ListInviteCodes(c *gin.Context) {
	codes, err := h.inviteService.ListInviteCodes(c.Request.Context())
	if err != nil {
		response.InternalError(c, "failed to list invite codes")
		return
	}

	response.Success(c, codes)
}
