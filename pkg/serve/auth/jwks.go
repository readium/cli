package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type JWKSAuthProvider struct {
	kf     keyfunc.Keyfunc
	parser *jwt.Parser
}

func (j *JWKSAuthProvider) Validate(token string) (string, int, error) {
	t, err := j.parser.Parse(token, j.kf.Keyfunc)
	if err != nil {
		if errors.Is(err, jwkset.ErrKeyNotFound) {
			return "", http.StatusBadRequest, err
		} else if errors.Is(err, jwt.ErrTokenMalformed) {
			return "", http.StatusBadRequest, err
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return "", http.StatusBadRequest, err
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return "", http.StatusGone, err
		} else {
			return "", http.StatusInternalServerError, err
		}
	}
	if !t.Valid {
		return "", http.StatusBadRequest, errors.New("invalid JWT token")
	}
	subject, err := t.Claims.GetSubject()
	if err != nil {
		return "", http.StatusBadRequest, errors.New("failed extracting subject from JWT")
	}
	if subject == "" {
		return "", http.StatusBadRequest, errors.New("JWT subject is empty")
	}

	return subject, http.StatusOK, nil
}

func NewJWKSAuthProvider(context context.Context, client *http.Client, jwksUrl string) (*JWKSAuthProvider, error) {
	if len(jwksUrl) == 0 {
		return nil, errors.New("JWKS URL is empty")
	}

	kf, err := keyfunc.NewDefaultOverrideCtx(context, []string{jwksUrl}, keyfunc.Override{
		Client:          client,
		RefreshInterval: time.Hour * 12,
	})
	if err != nil {
		return nil, err
	}

	return &JWKSAuthProvider{
		kf:     kf,
		parser: jwt.NewParser(),
	}, nil
}
