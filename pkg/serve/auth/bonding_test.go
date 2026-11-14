package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSharedSecret = "test-shared-secret"
	safariUA         = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15"
	chromeUA         = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
)

func newTestBondingProvider(t *testing.T) *JWTBondingAuthProvider {
	t.Helper()
	p, err := NewJWTBondingAuthProvider([]byte(testSharedSecret), []byte("test-bonding-secret"), 1, 0, time.Minute, 0, "", "")
	require.NoError(t, err)
	return p
}

// startBonding performs the first leg of the exchange: a fresh JWT is answered
// with a 302 to a bonding JWT, along with the device cookie.
func startBonding(t *testing.T, p *JWTBondingAuthProvider, header http.Header) (string, *http.Cookie) {
	t.Helper()
	fresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "session:https://example.com/session.json",
	}).SignedString([]byte(testSharedSecret))
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/webpub/"+fresh+"/manifest.json", nil)
	r.Header = header.Clone()
	w := httptest.NewRecorder()
	_, authErr := p.Validate(w, r, fresh)
	require.NotNil(t, authErr)
	require.Equal(t, http.StatusFound, authErr.StatusCode)
	require.True(t, strings.HasPrefix(authErr.RedirectPath, "bonding."))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "bonding-device", cookies[0].Name)
	return authErr.RedirectPath, cookies[0]
}

// TestBondingRedirectHop replays the second leg of the exchange: the request a
// browser makes when it follows the bonding 302. Safari sends Accept-Language
// on the first leg but not on this one, which must not break the agent hash.
func TestBondingRedirectHop(t *testing.T) {
	firstLeg := http.Header{
		"User-Agent":      {safariUA},
		"Accept-Language": {"en-US,en;q=0.9"},
	}

	tests := []struct {
		name       string
		header     http.Header
		withCookie bool
		wantStatus int // 0 means the bonding JWT is accepted
		wantErr    string
	}{
		{
			name:       "Safari drops Accept-Language on the redirect",
			header:     http.Header{"User-Agent": {safariUA}},
			withCookie: true,
		},
		{
			name:       "same headers as the first leg",
			header:     firstLeg,
			withCookie: true,
		},
		{
			name:       "different Accept-Language",
			header:     http.Header{"User-Agent": {safariUA}, "Accept-Language": {"fi-FI,fi;q=0.9"}},
			withCookie: true,
		},
		{
			name:       "different User-Agent",
			header:     http.Header{"User-Agent": {chromeUA}, "Accept-Language": {"en-US,en;q=0.9"}},
			withCookie: true,
			wantStatus: http.StatusForbidden,
			wantErr:    "browser integrity mismatch",
		},
		{
			name:       "missing device cookie",
			header:     firstLeg,
			withCookie: false,
			wantStatus: http.StatusForbidden,
			wantErr:    "device integrity mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestBondingProvider(t)
			bondingToken, cookie := startBonding(t, p, firstLeg)

			r := httptest.NewRequest(http.MethodGet, "/webpub/"+bondingToken+"/manifest.json", nil)
			r.Header = tt.header.Clone()
			if tt.withCookie {
				r.AddCookie(cookie)
			}
			out, authErr := p.Validate(httptest.NewRecorder(), r, bondingToken)

			if tt.wantStatus == 0 {
				require.Nil(t, authErr)
				_, ok := out.Context().Value(BondingRecordContextKey).(BondingData)
				assert.True(t, ok, "bonding record should be set in the request context")
				return
			}
			require.NotNil(t, authErr)
			assert.Equal(t, tt.wantStatus, authErr.StatusCode)
			assert.EqualError(t, authErr.Err, tt.wantErr)
		})
	}
}
