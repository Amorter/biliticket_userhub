package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeID      TokenType = "id"
)

// Claims extends jwt.RegisteredClaims with custom fields.
type Claims struct {
	jwt.RegisteredClaims
	TokenType TokenType `json:"token_type"`
}

type Manager struct {
	signingKey      []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	idTokenTTL      time.Duration
}

func NewManager(signingKey string, issuer string, accessTTL, refreshTTL, idTTL time.Duration) *Manager {
	return &Manager{
		signingKey:      []byte(signingKey),
		issuer:          issuer,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		idTokenTTL:      idTTL,
	}
}

// GenerateAccessToken creates a signed JWT access token for a given user ID.
func (m *Manager) GenerateAccessToken(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTokenTTL)),
			ID:        uuid.New().String(),
		},
		TokenType: TokenTypeAccess,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.signingKey)
}

// GenerateRefreshToken creates a signed JWT refresh token.
// Returns the token string and claims (caller can use claims.ID to store JTI in StateStore for revocation).
func (m *Manager) GenerateRefreshToken(userID uuid.UUID) (string, *Claims, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshTokenTTL)),
			ID:        uuid.New().String(),
		},
		TokenType: TokenTypeRefresh,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.signingKey)
	if err != nil {
		return "", nil, err
	}
	return signed, &claims, nil
}

// GenerateIDToken creates a signed JWT ID token with user claims.
func (m *Manager) GenerateIDToken(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.idTokenTTL)),
			ID:        uuid.New().String(),
		},
		TokenType: TokenTypeID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.signingKey)
}

// Validate parses and validates a token string, returning claims.
func (m *Manager) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.Issuer != m.issuer {
		return nil, errors.New("invalid issuer")
	}

	return claims, nil
}
