package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server            ServerConfig            `mapstructure:"server"`
	Database          DatabaseConfig          `mapstructure:"database"`
	State             StateConfig             `mapstructure:"state"`
	JWT               JWTConfig               `mapstructure:"jwt"`
	OIDC              OIDCConfig              `mapstructure:"oidc"`
	OAuth2            OAuth2Config            `mapstructure:"oauth2"`
	WebAuthn          WebAuthnConfig          `mapstructure:"webauthn"`
	Invite            InviteConfig            `mapstructure:"invite"`
	Admin             AdminConfig             `mapstructure:"admin"`
	EmailVerification EmailVerificationConfig `mapstructure:"email_verification"`
	SMTP              SMTPConfig              `mapstructure:"smtp"`
	CORS              CORSConfig              `mapstructure:"cors"`
	Log               LogConfig               `mapstructure:"log"`
}

type ServerConfig struct {
	Host                    string        `mapstructure:"host"`
	Port                    int           `mapstructure:"port"`
	Mode                    string        `mapstructure:"mode"`
	ReadTimeout             time.Duration `mapstructure:"read_timeout"`
	WriteTimeout            time.Duration `mapstructure:"write_timeout"`
	GracefulShutdownTimeout time.Duration `mapstructure:"graceful_shutdown_timeout"`
}

type DatabaseConfig struct {
	Postgres PostgresConfig `mapstructure:"postgres"`
	Redis    RedisConfig    `mapstructure:"redis"`
}

type PostgresConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	DB              string        `mapstructure:"db"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	AutoMigrate     bool          `mapstructure:"auto_migrate"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"pool_size"`
}

type StateConfig struct {
	Backend string `mapstructure:"backend"` // "redis" | "memory"
}

type JWTConfig struct {
	SigningKey      string        `mapstructure:"signing_key"`
	Issuer          string        `mapstructure:"issuer"`
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
	IDTokenTTL      time.Duration `mapstructure:"id_token_ttl"`
}

type InviteConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type AdminConfig struct {
	UserIDs []string `mapstructure:"user_ids"` // List of admin user UUIDs
}

type OIDCConfig struct {
	Issuer    string `mapstructure:"issuer"`     // OIDC issuer URL (e.g. https://auth.example.com)
	CryptoKey string `mapstructure:"crypto_key"` // 32-byte key for encrypting auth codes
	LoginURL  string `mapstructure:"login_url"`  // Frontend login page URL template
}

type OAuth2Config struct {
	GitHub OAuth2ProviderConfig `mapstructure:"github"`
	Google OAuth2ProviderConfig `mapstructure:"google"`
}

type OAuth2ProviderConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"` // Our callback URL
	Scopes       []string `mapstructure:"scopes"`
}

type WebAuthnConfig struct {
	RPDisplayName string   `mapstructure:"rp_display_name"`
	RPID          string   `mapstructure:"rp_id"`
	RPOrigins     []string `mapstructure:"rp_origins"`
}

type CORSConfig struct {
	AllowedOrigins   []string      `mapstructure:"allowed_origins"`
	AllowedMethods   []string      `mapstructure:"allowed_methods"`
	AllowedHeaders   []string      `mapstructure:"allowed_headers"`
	AllowCredentials bool          `mapstructure:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type EmailVerificationConfig struct {
	Enabled                    bool          `mapstructure:"enabled"`
	RequireVerifiedForRegister bool          `mapstructure:"require_verified_for_register"`
	RequireVerifiedForLogin    bool          `mapstructure:"require_verified_for_login"`
	TokenTTL                   time.Duration `mapstructure:"token_ttl"`
	VerifyURLTemplate          string        `mapstructure:"verify_url_template"` // e.g. https://app.example.com/verify-email?token={{TOKEN}}
	TokenSizeBytes             int           `mapstructure:"token_size_bytes"`    // random bytes length before base64url encoding
}

type SMTPConfig struct {
	Host          string `mapstructure:"host"`
	Port          int    `mapstructure:"port"`
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	FromEmail     string `mapstructure:"from_email"`
	FromName      string `mapstructure:"from_name"`
	UseSTARTTLS   bool   `mapstructure:"use_starttls"`
	SkipTLSVerify bool   `mapstructure:"skip_tls_verify"`
}

// Load reads base config, then optional local override config, overlays environment variables, and returns Config.
func Load(basePath string, localOverridePath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Environment variable override: DATABASE_POSTGRES_HOST -> database.postgres.host
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := mergeConfigFile(v, basePath, true); err != nil {
		return nil, err
	}
	if err := mergeConfigFile(v, localOverridePath, false); err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func mergeConfigFile(v *viper.Viper, path string, required bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		if required {
			return errors.New("base config path is required")
		}
		return nil
	}

	v.SetConfigFile(path)

	var err error
	if required {
		err = v.ReadInConfig()
	} else {
		err = v.MergeInConfig()
	}
	if err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !required && (errors.As(err, &notFound) || os.IsNotExist(err)) {
			return nil
		}
		return fmt.Errorf("load config file %s: %w", path, err)
	}
	return nil
}
