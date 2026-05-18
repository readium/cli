package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

type B64EncodedAuthProvider struct{}

func (n *B64EncodedAuthProvider) Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *AuthError) {
	path, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("invalid base64url path: %w", err)}
	}
	return r.WithContext(context.WithValue(r.Context(), ContextPathKey, string(path))), nil
}

func NewB64EncodedAuthProvider() *B64EncodedAuthProvider {
	return &B64EncodedAuthProvider{}
}
