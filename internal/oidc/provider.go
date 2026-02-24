package oidc

import (
	"crypto/sha256"
	"log/slog"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"biliticket/userhub/internal/config"
	"biliticket/userhub/internal/repository"
)

// SetupProvider creates a new OIDC OpenID Provider and its Storage.
func SetupProvider(
	cfg config.OIDCConfig,
	oidcClientRepo repository.OIDCClientRepository,
	userRepo repository.UserRepository,
	identityRepo repository.IdentityRepository,
	stateStore repository.StateStore,
	accessTTL, refreshTTL time.Duration,
) (op.OpenIDProvider, *Storage, error) {
	// Generate signing key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	storage := NewStorage(
		oidcClientRepo, userRepo, identityRepo, stateStore,
		keyPair, cfg.LoginURL,
		accessTTL, refreshTTL,
	)

	// Derive 32-byte crypto key from config
	cryptoKey := sha256.Sum256([]byte(cfg.CryptoKey))

	opConfig := &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
	}

	provider, err := op.NewProvider(
		opConfig,
		storage,
		op.StaticIssuer(cfg.Issuer),
		op.WithAllowInsecure(),
		op.WithLogger(slog.Default()),
	)
	if err != nil {
		return nil, nil, err
	}

	return provider, storage, nil
}
