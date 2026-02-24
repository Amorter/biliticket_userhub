package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/op"
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
	identityHandler *IdentityHandler,
	oidcHandler *OIDCHandler,
	oidcProvider op.OpenIDProvider,
	oauth2Handler *OAuth2Handler,
	webAuthnHandler *WebAuthnHandler,
	adminHandler *AdminHandler,
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

	// OIDC Provider endpoints (/oidc/authorize, /oidc/token, /oidc/userinfo, etc.)
	if oidcProvider != nil {
		MountOIDCProvider(r, oidcProvider)
	}

	// Public auth routes
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)

		// OAuth2 social login (public)
		if oauth2Handler != nil {
			auth.GET("/oauth2/:provider/authorize", oauth2Handler.Authorize)
			auth.GET("/oauth2/:provider/callback", oauth2Handler.Callback)
		}

		// Passkey login (public)
		if webAuthnHandler != nil {
			auth.POST("/passkey/login/begin", webAuthnHandler.BeginLogin)
			auth.POST("/passkey/login/finish", webAuthnHandler.FinishLogin)
		}
	}

	// Protected routes
	protected := r.Group("/api/v1")
	protected.Use(middleware.JWTAuth(jwtManager))
	{
		protected.POST("/auth/logout", authHandler.Logout)

		// Identity management
		protected.POST("/identities/bind", identityHandler.Bind)
		protected.DELETE("/identities/:id", identityHandler.Unbind)
		protected.GET("/identities", identityHandler.List)

		// OAuth2 identity binding (requires auth)
		if oauth2Handler != nil {
			protected.POST("/identities/oauth2/:provider/bind", oauth2Handler.BindAuthorize)
			protected.GET("/identities/oauth2/:provider/callback", oauth2Handler.BindCallback)
		}

		// Passkey registration (requires auth)
		if webAuthnHandler != nil {
			protected.POST("/auth/passkey/register/begin", webAuthnHandler.BeginRegistration)
			protected.POST("/auth/passkey/register/finish", webAuthnHandler.FinishRegistration)
		}

		// OIDC login completion (user must be authenticated)
		if oidcHandler != nil {
			protected.POST("/oidc/login/complete", oidcHandler.CompleteLogin)
		}
	}

	// Admin routes (JWT + admin check)
	if adminHandler != nil {
		admin := r.Group("/api/v1/admin")
		admin.Use(middleware.JWTAuth(jwtManager))
		admin.Use(middleware.AdminAuth(cfg.Admin.UserIDs))
		{
			admin.POST("/invite-codes", adminHandler.CreateInviteCode)
			admin.GET("/invite-codes", adminHandler.ListInviteCodes)

			admin.POST("/oidc-clients", adminHandler.CreateOIDCClient)
			admin.GET("/oidc-clients", adminHandler.ListOIDCClients)
			admin.GET("/oidc-clients/:client_id", adminHandler.GetOIDCClient)
			admin.PUT("/oidc-clients/:client_id", adminHandler.UpdateOIDCClient)
			admin.DELETE("/oidc-clients/:client_id", adminHandler.DeleteOIDCClient)
			admin.POST("/oidc-clients/:client_id/rotate-secret", adminHandler.RotateOIDCClientSecret)
		}
	}

	return r
}
