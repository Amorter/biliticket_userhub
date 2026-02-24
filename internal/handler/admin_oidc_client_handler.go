package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type CreateOIDCClientRequest struct {
	ClientID      string   `json:"client_id" binding:"required"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	Name          string   `json:"name" binding:"required"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	IsFirstParty  bool     `json:"is_first_party"`
}

type UpdateOIDCClientRequest struct {
	Name          string   `json:"name" binding:"required"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	IsFirstParty  *bool    `json:"is_first_party" binding:"required"`
}

func (h *AdminHandler) CreateOIDCClient(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	var req CreateOIDCClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request body: "+err.Error())
		return
	}

	created, err := h.oidcClientService.Create(c.Request.Context(), service.CreateOIDCClientInput{
		ClientID:      req.ClientID,
		ClientSecret:  req.ClientSecret,
		Name:          req.Name,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		IsFirstParty:  req.IsFirstParty,
	})
	if err != nil {
		h.handleOIDCClientError(c, err, "failed to create oidc client")
		return
	}

	response.Success(c, gin.H{
		"client":        created.Client,
		"client_secret": created.ClientSecret,
	})
}

func (h *AdminHandler) ListOIDCClients(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	clients, err := h.oidcClientService.List(c.Request.Context())
	if err != nil {
		response.InternalError(c, "failed to list oidc clients")
		return
	}

	response.Success(c, clients)
}

func (h *AdminHandler) GetOIDCClient(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	clientID := c.Param("client_id")
	client, err := h.oidcClientService.Get(c.Request.Context(), clientID)
	if err != nil {
		h.handleOIDCClientError(c, err, "failed to get oidc client")
		return
	}

	response.Success(c, client)
}

func (h *AdminHandler) UpdateOIDCClient(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	var req UpdateOIDCClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request body: "+err.Error())
		return
	}

	clientID := c.Param("client_id")
	client, err := h.oidcClientService.Update(c.Request.Context(), clientID, service.UpdateOIDCClientInput{
		Name:          req.Name,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		IsFirstParty:  *req.IsFirstParty,
	})
	if err != nil {
		h.handleOIDCClientError(c, err, "failed to update oidc client")
		return
	}

	response.Success(c, client)
}

func (h *AdminHandler) DeleteOIDCClient(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	clientID := c.Param("client_id")
	if err := h.oidcClientService.Delete(c.Request.Context(), clientID); err != nil {
		h.handleOIDCClientError(c, err, "failed to delete oidc client")
		return
	}

	response.Success(c, nil)
}

func (h *AdminHandler) RotateOIDCClientSecret(c *gin.Context) {
	if h.oidcClientService == nil {
		response.InternalError(c, "oidc client service not configured")
		return
	}

	clientID := c.Param("client_id")
	clientSecret, err := h.oidcClientService.RotateSecret(c.Request.Context(), clientID)
	if err != nil {
		h.handleOIDCClientError(c, err, "failed to rotate oidc client secret")
		return
	}

	response.Success(c, gin.H{
		"client_id":     clientID,
		"client_secret": clientSecret,
	})
}

func (h *AdminHandler) handleOIDCClientError(c *gin.Context, err error, internalErrMsg string) {
	switch {
	case errors.Is(err, service.ErrOIDCClientInvalid):
		response.BadRequest(c, err.Error())
	case errors.Is(err, service.ErrOIDCClientExists):
		response.Error(c, 409, 409, err.Error())
	case errors.Is(err, service.ErrOIDCClientNotFound):
		response.Error(c, 404, 404, err.Error())
	default:
		response.InternalError(c, internalErrMsg)
	}
}
