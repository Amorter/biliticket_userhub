package oidc

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"biliticket/userhub/internal/model"
)

// Client wraps model.OIDCClient to implement op.Client.
type Client struct {
	model    *model.OIDCClient
	loginURL string // login URL template
}

func NewClient(m *model.OIDCClient, loginURLTemplate string) *Client {
	return &Client{model: m, loginURL: loginURLTemplate}
}

func (c *Client) GetID() string                { return c.model.ClientID }
func (c *Client) RedirectURIs() []string       { return []string(c.model.RedirectURIs) }
func (c *Client) PostLogoutRedirectURIs() []string { return nil }

func (c *Client) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	return oidc.AuthMethodBasic
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *Client) GrantTypes() []oidc.GrantType {
	types := []oidc.GrantType{oidc.GrantTypeCode}
	// All clients support refresh tokens
	types = append(types, oidc.GrantTypeRefreshToken)
	return types
}

func (c *Client) LoginURL(authRequestID string) string {
	return LoginURL(c.loginURL, authRequestID)
}

func (c *Client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}

func (c *Client) IDTokenLifetime() time.Duration {
	return 1 * time.Hour
}

func (c *Client) DevMode() bool {
	return false
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.model.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *Client) ClockSkew() time.Duration {
	return 0
}
