package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// AuthRequest implements op.AuthRequest.
type AuthRequest struct {
	ID            string              `json:"id"`
	ClientID      string              `json:"client_id"`
	RedirectURI   string              `json:"redirect_uri"`
	Scopes        []string            `json:"scopes"`
	ResponseType  oidc.ResponseType   `json:"response_type"`
	ResponseMode  oidc.ResponseMode   `json:"response_mode,omitempty"`
	State         string              `json:"state"`
	Nonce         string              `json:"nonce"`
	CodeChallenge *oidcCodeChallenge  `json:"code_challenge,omitempty"`
	UserID        string              `json:"user_id,omitempty"`
	AuthTime      time.Time           `json:"auth_time,omitempty"`
	IsDone        bool                `json:"is_done"`
	CreatedAt     time.Time           `json:"created_at"`
}

type oidcCodeChallenge struct {
	Challenge string `json:"challenge"`
	Method    string `json:"method"`
}

func (a *AuthRequest) GetID() string                          { return a.ID }
func (a *AuthRequest) GetACR() string                         { return "" }
func (a *AuthRequest) GetAMR() []string {
	if a.IsDone {
		return []string{"pwd"}
	}
	return nil
}
func (a *AuthRequest) GetAudience() []string                  { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time                 { return a.AuthTime }
func (a *AuthRequest) GetClientID() string                    { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == nil {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge.Challenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallenge.Method),
	}
}
func (a *AuthRequest) GetNonce() string                       { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                 { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType     { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode     { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                    { return a.Scopes }
func (a *AuthRequest) GetState() string                       { return a.State }
func (a *AuthRequest) GetSubject() string                     { return a.UserID }
func (a *AuthRequest) Done() bool                             { return a.IsDone }

func (a *AuthRequest) Marshal() ([]byte, error) {
	return json.Marshal(a)
}

func UnmarshalAuthRequest(data []byte) (*AuthRequest, error) {
	var req AuthRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// authRequestFromOIDC converts the library's oidc.AuthRequest into our AuthRequest.
func authRequestFromOIDC(oidcReq *oidc.AuthRequest, id string) *AuthRequest {
	req := &AuthRequest{
		ID:           id,
		ClientID:     oidcReq.ClientID,
		RedirectURI:  oidcReq.RedirectURI,
		Scopes:       oidcReq.Scopes,
		ResponseType: oidcReq.ResponseType,
		ResponseMode: oidcReq.ResponseMode,
		State:        oidcReq.State,
		Nonce:        oidcReq.Nonce,
		CreatedAt:    time.Now(),
	}
	if oidcReq.CodeChallenge != "" {
		req.CodeChallenge = &oidcCodeChallenge{
			Challenge: oidcReq.CodeChallenge,
			Method:    string(oidcReq.CodeChallengeMethod),
		}
	}
	return req
}

// CompleteAuthRequest marks the auth request as done with the given user ID.
func (a *AuthRequest) CompleteAuthRequest(userID string) {
	a.UserID = userID
	a.IsDone = true
	a.AuthTime = time.Now()
}

// LoginURL generates the login URL for the given auth request ID using the template.
func LoginURL(template string, authRequestID string) string {
	return strings.Replace(template, "{{ID}}", authRequestID, 1)
}
