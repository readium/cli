package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

type B64EncodedAuthProvider struct{}

func (n *B64EncodedAuthProvider) Validate(token string) (string, int, error) {
	path, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("invalid base64url path: %w", err)
	}
	return string(path), http.StatusOK, nil
}

func NewB64EncodedAuthProvider() *B64EncodedAuthProvider {
	return &B64EncodedAuthProvider{}
}
