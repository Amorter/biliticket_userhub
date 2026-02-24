package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	jwtpkg "biliticket/userhub/pkg/jwt"
	"biliticket/userhub/pkg/response"
)

// AdminAuth checks that the authenticated user is in the admin user list.
// Must be used after JWTAuth middleware.
func AdminAuth(adminUserIDs []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(adminUserIDs))
	for _, id := range adminUserIDs {
		allowed[id] = struct{}{}
	}

	return func(c *gin.Context) {
		claimsVal, exists := c.Get(ContextKeyUserClaims)
		if !exists {
			response.Unauthorized(c, "missing authentication")
			c.Abort()
			return
		}
		claims, ok := claimsVal.(*jwtpkg.Claims)
		if !ok {
			response.Unauthorized(c, "invalid claims")
			c.Abort()
			return
		}

		// Validate UUID format and check against allow list
		if _, err := uuid.Parse(claims.Subject); err != nil {
			response.Unauthorized(c, "invalid user id")
			c.Abort()
			return
		}

		if _, isAdmin := allowed[claims.Subject]; !isAdmin {
			response.Forbidden(c, "admin access required")
			c.Abort()
			return
		}

		c.Next()
	}
}
