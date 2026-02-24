package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// signingKey implements op.SigningKey using an RSA private key.
type signingKey struct {
	id         string
	algorithm  jose.SignatureAlgorithm
	privateKey *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.algorithm }
func (s *signingKey) Key() any                                    { return s.privateKey }
func (s *signingKey) ID() string                                  { return s.id }

// publicKey implements op.Key using an RSA public key.
type publicKey struct {
	signingKey
}

func (p *publicKey) Algorithm() jose.SignatureAlgorithm { return p.signingKey.algorithm }
func (p *publicKey) Use() string                        { return "sig" }
func (p *publicKey) Key() any                           { return &p.signingKey.privateKey.PublicKey }
func (p *publicKey) ID() string                         { return p.signingKey.id }

// KeyPair holds a signing key and its public counterpart.
type KeyPair struct {
	signing *signingKey
	public  *publicKey
}

func (kp *KeyPair) SigningKey() op.SigningKey { return kp.signing }
func (kp *KeyPair) PublicKey() op.Key        { return kp.public }

// GenerateKeyPair creates a new RSA-2048 key pair for OIDC token signing.
func GenerateKeyPair() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Derive a stable key ID from the public key
	pubBytes := key.PublicKey.N.Bytes()
	hash := sha256.Sum256(pubBytes)
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	sk := &signingKey{
		id:         kid,
		algorithm:  jose.RS256,
		privateKey: key,
	}

	return &KeyPair{
		signing: sk,
		public:  &publicKey{signingKey: *sk},
	}, nil
}
