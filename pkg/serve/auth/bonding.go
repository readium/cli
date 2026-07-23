package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/maypok86/otter/v2"
	"github.com/pkg/errors"
	"github.com/readium/cli/internal/version"
	"lukechampine.com/blake3"
)

type BondingEvictionProvider interface {
	Evict(excess uint16) error
}

type AgentBond struct {
	Hash      [32]byte
	Device    uuid.UUID
	UpdatedAt time.Time
}

// A BondingAuthProvider MUST set the BondingRecordContextKey in the request context.
type BondingAuthProvider interface {
	MaxDevices() uint16
	MinDeviceEvictionInterval() time.Duration
	MaxBondsPerSubject() uint16
	Cache() *otter.Cache[string, []AgentBond]
}

type BondingData struct {
	Hash   [32]byte
	Device uuid.UUID
	Key    string
}

func EvictBonds(bonds []AgentBond, keep uint16) []AgentBond {
	if uint16(len(bonds)) <= keep {
		return bonds
	}
	slices.SortFunc(bonds, func(x, y AgentBond) int {
		return y.UpdatedAt.Compare(x.UpdatedAt)
	})
	return bonds[:keep]
}

const bondingJwtAudience = "bonding"

type bondingJwtClaims struct {
	jwt.RegisteredClaims
	DeviceHash string `json:"dh"`
	AgentHash  string `json:"ah"`
}

func jwtErrorToHTTPStatus(err error) int {
	if errors.Is(err, jwkset.ErrKeyNotFound) {
		return http.StatusBadRequest
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		return http.StatusBadRequest
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return http.StatusBadRequest
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		return http.StatusGone
	} else {
		return http.StatusInternalServerError
	}
}

type bondingCore struct {
	bondingSecret             []byte
	agentHashKey              [32]byte
	hasherPool                sync.Pool
	bondingParser             *jwt.Parser
	cache                     *otter.Cache[string, []AgentBond]
	jtiCache                  *otter.Cache[string, struct{}]
	defaultBondingMaxDevices  uint16
	maxBondsPerSubject        uint16
	minDeviceEvictionInterval time.Duration
	cookiePrefix              string
	cookieSubfolder           string
	jwtPrefix                 string
}

func (b *bondingCore) MaxDevices() uint16 {
	return b.defaultBondingMaxDevices
}

func (b *bondingCore) MinDeviceEvictionInterval() time.Duration {
	return b.minDeviceEvictionInterval
}

func (b *bondingCore) MaxBondsPerSubject() uint16 {
	return b.maxBondsPerSubject
}

func (b *bondingCore) Cache() *otter.Cache[string, []AgentBond] {
	return b.cache
}

func (b *bondingCore) agentHash(deviceID uuid.UUID, r *http.Request) [32]byte {
	h := b.hasherPool.Get().(*blake3.Hasher)
	defer b.hasherPool.Put(h)
	h.Reset()
	h.Write([]byte("agent|"))
	h.Write(deviceID[:])
	h.Write([]byte{'|'})
	h.Write([]byte(r.Header.Get("User-Agent")))
	h.Write([]byte{'|'})
	h.Write([]byte(r.Header.Get("Accept-Language")))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (b *bondingCore) deviceHash(deviceID uuid.UUID) [32]byte {
	h := b.hasherPool.Get().(*blake3.Hasher)
	defer b.hasherPool.Put(h)
	h.Reset()
	h.Write([]byte("device|"))
	h.Write(deviceID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (b *bondingCore) setCookie(w http.ResponseWriter, name, value string, refreshTTL time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:        b.cookiePrefix + "-" + name,
		Value:       value,
		Path:        "/" + b.cookieSubfolder,
		MaxAge:      int(refreshTTL.Seconds()),
		Secure:      true,
		SameSite:    http.SameSiteNoneMode,
		HttpOnly:    true,
		Partitioned: true,
	})
}

func (b *bondingCore) getOrCreateDeviceID(r *http.Request) (uuid.UUID, *AuthError) {
	if c, err := r.Cookie(b.cookiePrefix + "-device"); err == nil {
		if id, err := uuid.Parse(c.Value); err == nil {
			return id, nil
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.Wrap(err, "failed generating UUID for device bonding")}
	}
	return id, nil
}

func (b *bondingCore) validateBondingJWT(w http.ResponseWriter, r *http.Request, deviceID uuid.UUID, token string) (*http.Request, *AuthError) {
	var claims bondingJwtClaims
	t, err := b.bondingParser.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return b.bondingSecret, nil
	})
	if err != nil {
		return nil, &AuthError{StatusCode: jwtErrorToHTTPStatus(err), Err: err}
	}
	if !t.Valid {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid JWT token")}
	}
	audience, err := claims.GetAudience()
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("failed extracting audience from JWT")}
	}
	if len(audience) != 1 || audience[0] != bondingJwtAudience {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("JWT audience is invalid")}
	}
	subject, err := claims.GetSubject()
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.New("failed extracting subject from JWT")}
	}

	claimDevice, err := base64.RawURLEncoding.DecodeString(claims.DeviceHash)
	if err != nil || len(claimDevice) != 32 {
		return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.New("invalid device hash in JWT")}
	}
	claimAgent, err := base64.RawURLEncoding.DecodeString(claims.AgentHash)
	if err != nil || len(claimAgent) != 32 {
		return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.New("invalid agent hash in JWT")}
	}

	curDevice := b.deviceHash(deviceID)
	curAgent := b.agentHash(deviceID, r)
	if !bytes.Equal(curDevice[:], claimDevice) {
		return nil, &AuthError{StatusCode: http.StatusForbidden, Err: errors.New("device integrity mismatch")}
	}
	if !bytes.Equal(curAgent[:], claimAgent) {
		return nil, &AuthError{StatusCode: http.StatusForbidden, Err: errors.New("browser integrity mismatch")}
	}

	b.setCookie(w, "device", deviceID.String(), time.Hour*24*90)

	// The subject's current bonds are read inside an atomic cache compute in
	// api.go's enforceBonding, not snapshotted here: a snapshot would make the
	// limit check a lost-update race across concurrent requests.
	bondData := BondingData{
		Key:    subject,
		Hash:   curAgent,
		Device: deviceID,
	}

	ctx := context.WithValue(r.Context(), BondingRecordContextKey, bondData)
	ctx = context.WithValue(ctx, ContextPathKey, subject)
	r = r.WithContext(ctx)
	return r, nil
}

// checkAndStoreJTI enforces single-use semantics for fresh CLI JWTs that
// carry a JTI claim. Tokens without a JTI are allowed through unchanged.
// The replay store lives in its own cache so JTI churn cannot evict bond
// records (which would reset a subject's device count), and SetIfAbsent
// makes the check-and-store atomic across concurrent requests.
func (b *bondingCore) checkAndStoreJTI(jti string) *AuthError {
	if jti == "" {
		return nil
	}
	if _, stored := b.jtiCache.SetIfAbsent(jti, struct{}{}); !stored {
		return &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("JWT token with jti claim has already been used")}
	}
	return nil
}

func (b *bondingCore) issueBondingJWT(w http.ResponseWriter, r *http.Request, deviceID uuid.UUID, subject string) (*http.Request, *AuthError) {
	b.setCookie(w, "device", deviceID.String(), time.Hour*24*90)

	curDevice := b.deviceHash(deviceID)
	curAgent := b.agentHash(deviceID, r)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, bondingJwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{bondingJwtAudience},
			Issuer:   "readium/" + version.Version,
			Subject:  subject,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		DeviceHash: base64.RawURLEncoding.EncodeToString(curDevice[:]),
		AgentHash:  base64.RawURLEncoding.EncodeToString(curAgent[:]),
	})
	tokStr, err := tok.SignedString(b.bondingSecret)
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.Wrap(err, "failed signing bonding JWT")}
	}
	return nil, &AuthError{StatusCode: http.StatusFound, RedirectPath: b.jwtPrefix + tokStr}
}

func (b *bondingCore) validateFreshJWT(w http.ResponseWriter, r *http.Request, deviceID uuid.UUID, token string, parser *jwt.Parser, keyfn jwt.Keyfunc) (*http.Request, *AuthError) {
	var claims jwt.RegisteredClaims
	t, err := parser.ParseWithClaims(token, &claims, keyfn)
	if err != nil {
		return nil, &AuthError{StatusCode: jwtErrorToHTTPStatus(err), Err: err}
	}
	if !t.Valid {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid JWT token")}
	}
	subject, err := claims.GetSubject()
	if err != nil {
		return nil, &AuthError{StatusCode: http.StatusBadRequest, Err: errors.New("failed extracting subject from JWT")}
	}
	if subject == "" {
		return nil, &AuthError{StatusCode: http.StatusInternalServerError, Err: errors.New("JWT subject is required")}
	}
	if authErr := b.checkAndStoreJTI(claims.ID); authErr != nil {
		return nil, authErr
	}
	return b.issueBondingJWT(w, r, deviceID, subject)
}

// newBondingCore initializes the shared bonding state. It validates the
// bonding secret, configures the cache and hasher pool, and derives the
// blake3 MAC key from the bonding secret.
func newBondingCore(bondingSecret []byte, defaultMaxDevices uint16, maxBondsPerSubject uint16, minDeviceEvictionInterval time.Duration, maxCacheSize uint, cookiePrefix, cookieSubfolder string) (*bondingCore, error) {
	if len(bondingSecret) < 8 {
		return nil, errors.New("length of bonding secret is less than 8 bytes")
	}
	if cookiePrefix == "" {
		cookiePrefix = "bonding"
	}
	for _, c := range cookiePrefix {
		// The prefix is used both in cookie names (RFC 6265 tokens) and in the
		// bonding redirect path, where a "/" or other special character would
		// not match the route's {path} pattern and break every exchange.
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.Errorf("cookie prefix contains unsupported character %q, use only letters, digits, '-' and '_'", c)
		}
	}
	if len(cookieSubfolder) > 0 {
		cookieSubfolder = strings.TrimLeft(cookieSubfolder, "/")
	}
	if maxCacheSize == 0 {
		maxCacheSize = 10_000
	} else if maxCacheSize < 100 {
		// Sanity check, and lets us hardcode the InitialCapacity below
		return nil, errors.New("bonding max cache size must be at least 100")
	}
	if minDeviceEvictionInterval <= 10*time.Second {
		// Sanity check
		return nil, errors.New("bonding minimum device eviction interval must be greater than 10 seconds")
	}
	if maxBondsPerSubject > 0 && maxBondsPerSubject < defaultMaxDevices {
		return nil, errors.New("max bonds per subject must be at least the default max devices")
	}

	c := &bondingCore{
		bondingSecret: bondingSecret,
		bondingParser: jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})),
		cache: otter.Must(&otter.Options[string, []AgentBond]{
			MaximumSize:     int(maxCacheSize),
			InitialCapacity: 100,
		}),
		jtiCache: otter.Must(&otter.Options[string, struct{}]{
			MaximumSize:     int(maxCacheSize),
			InitialCapacity: 100,
		}),
		defaultBondingMaxDevices:  defaultMaxDevices,
		maxBondsPerSubject:        maxBondsPerSubject,
		cookiePrefix:              cookiePrefix,
		cookieSubfolder:           cookieSubfolder,
		jwtPrefix:                 cookiePrefix + ".",
		minDeviceEvictionInterval: minDeviceEvictionInterval,
	}
	// Derive a separate 32-byte key for the blake3 MACs so we don't reuse the
	// JWT signing secret directly as a hash key.
	blake3.DeriveKey(c.agentHashKey[:], "readium-cli jwt-bonding agent hash v1", bondingSecret)
	c.hasherPool.New = func() any {
		return blake3.New(32, c.agentHashKey[:])
	}
	return c, nil
}
