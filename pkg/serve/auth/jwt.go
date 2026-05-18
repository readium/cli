package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

type JWTAuthProvider struct {
	sharedSecret []byte
	parser       *jwt.Parser
}

func (j *JWTAuthProvider) Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *AuthError) {
	t, err := j.parser.Parse(token, func(t *jwt.Token) (any, error) {
		// We're relying on the parser to enforce method HS256
		return j.sharedSecret, nil
	})
	if err != nil {
		if errors.Is(err, jwkset.ErrKeyNotFound) {
			return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: err}
		} else if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: err}
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: err}
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, &AuthError{StatusCode: http.StatusGone, Err: err}
		} else {
			return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: err}
		}
	}
	if !t.Valid {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid JWT token")}
	}
	subject, err := t.Claims.GetSubject()
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("failed extracting subject from JWT")}
	}
	if subject == "" {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("JWT subject is empty")}
	}

	return r.WithContext(context.WithValue(r.Context(), ContextPathKey, subject)), nil
}

func NewJWTAuthProvider(sharedSecret []byte) (*JWTAuthProvider, error) {
	if len(sharedSecret) < 8 {
		return nil, errors.New("length of JWT shared secret is less than 8 bytes")
	}

	return &JWTAuthProvider{
		sharedSecret: sharedSecret,
		parser:       jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})),
	}, nil
}
