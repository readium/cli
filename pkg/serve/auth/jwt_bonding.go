package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

type JWTBondingAuthProvider struct {
	*bondingCore
	sharedSecret []byte
	freshParser  *jwt.Parser
}

func (j *JWTBondingAuthProvider) Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *AuthError) {
	deviceID, authErr := j.getOrCreateDeviceID(r)
	if authErr != nil {
		return nil, authErr
	}

	if strings.HasPrefix(token, j.jwtPrefix) {
		return j.validateBondingJWT(w, r, deviceID, strings.TrimPrefix(token, j.jwtPrefix))
	}

	return j.validateFreshJWT(w, r, deviceID, token, j.freshParser, func(t *jwt.Token) (any, error) {
		return j.sharedSecret, nil
	})
}

func NewJWTBondingAuthProvider(sharedSecret []byte, bondingSecret []byte, defaultMaxDevices uint16, maxBondsPerSubject uint16, minDeviceEvictionInterval time.Duration, maxCacheSize uint, cookiePrefix, cookieSubfolder string) (*JWTBondingAuthProvider, error) {
	if len(sharedSecret) < 8 {
		return nil, errors.New("length of JWT shared secret is less than 8 bytes")
	}

	core, err := newBondingCore(bondingSecret, defaultMaxDevices, maxBondsPerSubject, minDeviceEvictionInterval, maxCacheSize, cookiePrefix, cookieSubfolder)
	if err != nil {
		return nil, err
	}

	return &JWTBondingAuthProvider{
		bondingCore:  core,
		sharedSecret: sharedSecret,
		freshParser:  jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})),
	}, nil
}
