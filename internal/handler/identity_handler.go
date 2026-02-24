package handler

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"biliticket/userhub/internal/model"
	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type IdentityHandler struct {
	identityService service.IdentityService
}

func NewIdentityHandler(identityService service.IdentityService) *IdentityHandler {
	return &IdentityHandler{identityService: identityService}
}

type BindIdentityRequest struct {
	IdentityType   string                 `json:"identity_type" binding:"required"`
	Identifier     string                 `json:"identifier" binding:"required"`
	CredentialData map[string]interface{} `json:"credential_data"`
}

func (h *IdentityHandler) Bind(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	var req BindIdentityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	identityType := model.IdentityType(req.IdentityType)
	if !isValidIdentityType(identityType) {
		response.BadRequest(c, "unsupported identity type")
		return
	}

	err = h.identityService.BindIdentity(
		c.Request.Context(),
		userID,
		identityType,
		req.Identifier,
		model.CredentialData(req.CredentialData),
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIdentityAlreadyExists):
			response.Error(c, 409, 409, err.Error())
		case errors.Is(err, service.ErrUserNotFound):
			response.Error(c, 404, 404, err.Error())
		case errors.Is(err, service.ErrUserDisabled):
			response.Error(c, 403, 403, err.Error())
		default:
			response.InternalError(c, "bind identity failed")
		}
		return
	}

	response.Success(c, nil)
}

func (h *IdentityHandler) Unbind(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	identityID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid identity id")
		return
	}

	err = h.identityService.UnbindIdentity(c.Request.Context(), userID, identityID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrCannotUnbindLast):
			response.BadRequest(c, err.Error())
		case errors.Is(err, service.ErrIdentityNotOwned):
			response.Error(c, 403, 403, err.Error())
		default:
			response.InternalError(c, "unbind identity failed")
		}
		return
	}

	response.Success(c, nil)
}

func (h *IdentityHandler) List(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		response.Unauthorized(c, "invalid user context")
		return
	}

	identities, err := h.identityService.ListIdentities(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "list identities failed")
		return
	}

	response.Success(c, identities)
}
