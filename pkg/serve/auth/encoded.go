package auth

import (
	"encoding/base64"
	"fmt"
)

type EncodedAuthProvider struct{}

func (n *EncodedAuthProvider) Validate(token string) (string, int, error) {
	path, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", 400, fmt.Errorf("invalid base64url path: %w", err)
	}
	return string(path), 200, nil
}

func NewEncodedAuthProvider() *EncodedAuthProvider {
	return &EncodedAuthProvider{}
}
