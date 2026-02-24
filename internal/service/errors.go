package service

import "errors"

var (
	ErrIdentityAlreadyExists = errors.New("identity already exists")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrInviteCodeRequired    = errors.New("invite code required")
	ErrInviteCodeInvalid     = errors.New("invite code invalid or expired")
	ErrInviteCodeExhausted   = errors.New("invite code usage exhausted")
	ErrRefreshTokenInvalid   = errors.New("refresh token invalid or revoked")
	ErrUserNotFound          = errors.New("user not found")
	ErrUserDisabled          = errors.New("user is disabled or banned")
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrCannotUnbindLast      = errors.New("cannot unbind last identity")
	ErrIdentityNotOwned      = errors.New("identity does not belong to this user")
	ErrUnsupportedIdentity   = errors.New("unsupported identity type for direct login")
)
