package handler

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/handler/middleware"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

func SetupRouter(
	cfg *config.Config,
	logger *zap.Logger,
	jwtManager *jwtpkg.Manager,
	authHandler *AuthHandler,
) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Global middleware
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.RequestLogger(logger))
	r.Use(middleware.CORS(cfg.CORS))

	// Health check
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Public auth routes
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
	}

	// Protected routes
	protected := r.Group("/api/v1")
	protected.Use(middleware.JWTAuth(jwtManager))
	{
		protected.POST("/auth/logout", authHandler.Logout)
	}

	return r
}
