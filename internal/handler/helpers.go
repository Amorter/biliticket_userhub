package handler

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"biliticket/userhub/internal/handler/middleware"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

func getUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	claimsVal, exists := c.Get(middleware.ContextKeyUserClaims)
	if !exists {
		return uuid.Nil, ErrNoClaims
	}
	claims, ok := claimsVal.(*jwtpkg.Claims)
	if !ok {
		return uuid.Nil, ErrNoClaims
	}
	return uuid.Parse(claims.Subject)
}

var ErrNoClaims = errors.New("claims not found in context")
