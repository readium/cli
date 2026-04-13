package auth

import "net/http"

type AuthProvider interface {
	Validate(r *http.Request, token string) (string, int, error)
}
