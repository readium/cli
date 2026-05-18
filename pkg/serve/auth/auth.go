package auth

import (
	"net/http"
)

type AuthError struct {
	StatusCode   int
	Err          error
	RedirectPath string
}

type AuthProvider interface {
	Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *AuthError)
}
