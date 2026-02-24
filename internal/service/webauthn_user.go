package service

import (
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"biliticket/userhub/internal/model"
)

// webauthnUser implements webauthn.User interface.
type webauthnUser struct {
	id          uuid.UUID
	credentials []webauthn.Credential
}

func newWebAuthnUser(userID uuid.UUID, identities []model.UserIdentity) *webauthnUser {
	var creds []webauthn.Credential
	for _, id := range identities {
		if id.IdentityType != model.IdentityTypePasskey {
			continue
		}
		cred, err := credentialFromIdentity(id)
		if err != nil {
			continue
		}
		creds = append(creds, *cred)
	}
	return &webauthnUser{id: userID, credentials: creds}
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *webauthnUser) WebAuthnName() string                       { return u.id.String() }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.id.String() }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// credentialFromIdentity deserializes a webauthn.Credential from identity's credential_data.
func credentialFromIdentity(identity model.UserIdentity) (*webauthn.Credential, error) {
	data, ok := identity.CredentialData["webauthn"]
	if !ok {
		return nil, ErrIdentityNotFound
	}
	// data is stored as a JSON object; re-marshal and unmarshal to webauthn.Credential
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(bytes, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// credentialToData serializes a webauthn.Credential into CredentialData for storage.
func credentialToData(cred *webauthn.Credential) model.CredentialData {
	bytes, _ := json.Marshal(cred)
	var data interface{}
	_ = json.Unmarshal(bytes, &data)
	return model.CredentialData{"webauthn": data}
}
