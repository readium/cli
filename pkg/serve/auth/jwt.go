package auth

import (
	"errors"
	"net/http"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

type JWTAuthProvider struct {
	sharedSecret []byte
	parser       *jwt.Parser
}

func (j *JWTAuthProvider) Validate(token string) (string, int, error) {
	t, err := j.parser.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// We're relying on the parser to enforce method HS256
		return j.sharedSecret, nil
	})
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

func NewJWTAuthProvider(sharedSecret []byte) (*JWTAuthProvider, error) {
	if len(sharedSecret) < 8 {
		return nil, errors.New("length of JWT shared secret is less than 8 bytes")
	}

	return &JWTAuthProvider{
		sharedSecret: sharedSecret,
		parser:       jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})),
	}, nil
}
