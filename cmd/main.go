package main

import (
	"context"
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
	"biliticket/userhub/internal/repository"
	"biliticket/userhub/internal/service"
	jwtpkg "biliticket/userhub/pkg/jwt"
)

func main() {
	// 1. Load configuration
	cfg, err := config.Load("config.yaml")
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

	// 7. Initialize JWT manager
	jwtManager := jwtpkg.NewManager(
		cfg.JWT.SigningKey,
		cfg.JWT.Issuer,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
		cfg.JWT.IDTokenTTL,
	)

	// 8. Initialize services
	authService := service.NewAuthService(
		userRepo, identityRepo, inviteRepo, stateStore,
		jwtManager, cfg.Invite.Enabled,
	)

	// 9. Initialize handlers
	authHandler := handler.NewAuthHandler(authService)

	// 10. Setup router
	router := handler.SetupRouter(cfg, logger, jwtManager, authHandler)

	// 11. Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 12. Start server with graceful shutdown
	go func() {
		logger.Info("server starting", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// 13. Wait for interrupt signal
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
