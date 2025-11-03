package auth

import (
	"encoding/base64"
	"fmt"
)

type B64EncodedAuthProvider struct{}

func (n *B64EncodedAuthProvider) Validate(token string) (string, int, error) {
	path, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", 400, fmt.Errorf("invalid base64url path: %w", err)
	}
	return string(path), 200, nil
}

func NewB64EncodedAuthProvider() *B64EncodedAuthProvider {
	return &B64EncodedAuthProvider{}
}
