package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	jwtpkg "biliticket/userhub/pkg/jwt"
	"biliticket/userhub/pkg/response"
)

const ContextKeyUserClaims = "user_claims"

func JWTAuth(jwtManager *jwtpkg.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Unauthorized(c, "missing authorization header")
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.Unauthorized(c, "invalid authorization format")
			c.Abort()
			return
		}

		claims, err := jwtManager.Validate(parts[1])
		if err != nil {
			response.Unauthorized(c, "invalid or expired token")
			c.Abort()
			return
		}

		if claims.TokenType != jwtpkg.TokenTypeAccess {
			response.Unauthorized(c, "invalid token type")
			c.Abort()
			return
		}

		c.Set(ContextKeyUserClaims, claims)
		c.Next()
	}
}
