package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

type JWKSBondingAuthProvider struct {
	*bondingCore
	kf          keyfunc.Keyfunc
	freshParser *jwt.Parser
}

func (j *JWKSBondingAuthProvider) Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *AuthError) {
	deviceID, authErr := j.getOrCreateDeviceID(r)
	if authErr != nil {
		return nil, authErr
	}

	if strings.HasPrefix(token, j.jwtPrefix) {
		return j.validateBondingJWT(w, r, deviceID, strings.TrimPrefix(token, j.jwtPrefix))
	}

	return j.validateFreshJWT(w, r, deviceID, token, j.freshParser, j.kf.Keyfunc)
}

func NewJWKSBondingAuthProvider(ctx context.Context, client *http.Client, jwksUrl string, bondingSecret []byte, defaultMaxDevices uint16, maxBondsPerSubject uint16, minDeviceEvictionInterval time.Duration, maxCacheSize uint, cookiePrefix, cookieSubfolder string) (*JWKSBondingAuthProvider, error) {
	if len(jwksUrl) == 0 {
		return nil, errors.New("JWKS URL is empty")
	}

	kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksUrl}, keyfunc.Override{
		Client:          client,
		RefreshInterval: time.Hour * 12,
	})
	if err != nil {
		return nil, err
	}

	core, err := newBondingCore(bondingSecret, defaultMaxDevices, maxBondsPerSubject, minDeviceEvictionInterval, maxCacheSize, cookiePrefix, cookieSubfolder)
	if err != nil {
		return nil, err
	}

	return &JWKSBondingAuthProvider{
		bondingCore: core,
		kf:          kf,
		freshParser: jwt.NewParser(),
	}, nil
}
