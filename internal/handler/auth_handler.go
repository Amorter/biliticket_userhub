package handler

import (
	"github.com/gin-gonic/gin"

	"biliticket/userhub/internal/service"
	"biliticket/userhub/pkg/response"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
	response.InternalError(c, "not implemented")
}

func (h *AuthHandler) Login(c *gin.Context) {
	response.InternalError(c, "not implemented")
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	response.InternalError(c, "not implemented")
}

func (h *AuthHandler) Logout(c *gin.Context) {
	response.InternalError(c, "not implemented")
}
