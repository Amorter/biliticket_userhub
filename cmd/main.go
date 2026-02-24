package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/handler"
	"biliticket/userhub/internal/model"
	oidcmod "biliticket/userhub/internal/oidc"
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/internal/service"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

func main() {
	baseConfigPath := flag.String("config", getenvOrDefault("CONFIG_FILE", "config.yaml"), "path to base config file")
	localConfigPath := flag.String("config-local", getenvOrDefault("CONFIG_LOCAL_FILE", "config.local.yaml"), "path to local override config file (optional)")
	flag.Parse()

	// 1. Load configuration
	cfg, err := config.Load(*baseConfigPath, *localConfigPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 2. Initialize logger
	var logger *zap.Logger
	if cfg.Log.Format == "json" {
		logger, _ = zap.NewProduction()
	} else {
		logger, _ = zap.NewDevelopment()
	}
	defer logger.Sync()

	// 3. Connect to PostgreSQL
	db, err := config.NewPostgresDB(cfg.Database.Postgres)
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}

	// 4. Auto-migrate if enabled
	if cfg.Database.Postgres.AutoMigrate {
		if err := model.AutoMigrate(db); err != nil {
			logger.Fatal("failed to auto-migrate", zap.Error(err))
		}
		logger.Info("database migration completed")
	}

	// 5. Initialize state store (Redis or in-memory)
	var stateStore repository.StateStore
	switch cfg.State.Backend {
	case "redis":
		redisClient, err := config.NewRedisClient(cfg.Database.Redis)
		if err != nil {
			logger.Fatal("failed to connect to redis", zap.Error(err))
		}
		stateStore = repository.NewRedisStateStore(redisClient)
		logger.Info("using Redis state store")
	case "memory":
		stateStore = repository.NewMemoryStateStore()
		logger.Info("using in-memory state store")
	default:
		logger.Fatal("unknown state backend", zap.String("backend", cfg.State.Backend))
	}

	// 6. Initialize repositories
	userRepo := repository.NewPGUserRepository(db)
	identityRepo := repository.NewPGIdentityRepository(db)
	inviteRepo := repository.NewPGInviteCodeRepository(db)
	oidcClientRepo := repository.NewPGOIDCClientRepository(db)

	// 7. Initialize JWT manager
	jwtManager := jwtpkg.NewManager(
		cfg.JWT.SigningKey,
		cfg.JWT.Issuer,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
		cfg.JWT.IDTokenTTL,
	)

	// 8. Initialize optional SMTP sender (email verification)
	var mailSender service.MailSender
	if cfg.EmailVerification.Enabled {
		if cfg.EmailVerification.VerifyURLTemplate == "" {
			logger.Fatal("email_verification.verify_url_template is required when email verification is enabled")
		}
		mailSender, err = service.NewSMTPSender(cfg.SMTP)
		if err != nil {
			logger.Fatal("failed to init smtp sender", zap.Error(err))
		}
		logger.Info("email verification enabled")
	}

	// 9. Initialize services
	authService := service.NewAuthService(
		userRepo, identityRepo, inviteRepo, stateStore,
		jwtManager, cfg.Invite.Enabled, cfg.EmailVerification, mailSender,
	)
	identityService := service.NewIdentityService(identityRepo, userRepo)
	oauth2Service := service.NewOAuth2Service(cfg.OAuth2, identityRepo, userRepo, stateStore, authService)

	// WebAuthn service
	var webAuthnService service.WebAuthnService
	if cfg.WebAuthn.RPID != "" {
		webAuthnService, err = service.NewWebAuthnService(cfg.WebAuthn, userRepo, identityRepo, stateStore, authService)
		if err != nil {
			logger.Fatal("failed to init webauthn service", zap.Error(err))
		}
		logger.Info("WebAuthn service initialized", zap.String("rp_id", cfg.WebAuthn.RPID))
	}

	// 10. Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	identityHandler := handler.NewIdentityHandler(identityService)
	oauth2Handler := handler.NewOAuth2Handler(oauth2Service)
	var webAuthnHandler *handler.WebAuthnHandler
	if webAuthnService != nil {
		webAuthnHandler = handler.NewWebAuthnHandler(webAuthnService)
	}

	// Invite & admin
	inviteService := service.NewInviteService(inviteRepo)
	oidcClientService := service.NewOIDCClientService(oidcClientRepo)
	adminHandler := handler.NewAdminHandler(inviteService, oidcClientService)

	// 11. Initialize OIDC Provider
	oidcProvider, oidcStorage, err := oidcmod.SetupProvider(
		cfg.OIDC,
		oidcClientRepo, userRepo, identityRepo, stateStore,
		cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL,
	)
	if err != nil {
		logger.Fatal("failed to setup OIDC provider", zap.Error(err))
	}
	oidcHandler := handler.NewOIDCHandler(oidcStorage, oidcProvider)
	logger.Info("OIDC provider initialized", zap.String("issuer", cfg.OIDC.Issuer))

	// 12. Setup router
	router := handler.SetupRouter(cfg, logger, jwtManager, authHandler, identityHandler, oidcHandler, oidcProvider, oauth2Handler, webAuthnHandler, adminHandler)

	// 13. Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 14. Start server with graceful shutdown
	go func() {
		logger.Info("server starting", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// 15. Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.GracefulShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("server forced to shutdown", zap.Error(err))
	}
	logger.Info("server exited gracefully")
}

func getenvOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
