package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const performanceBondingSecret = "performance-bonding-secret"

func newPerformanceBondingProvider(tb testing.TB) *JWTBondingAuthProvider {
	tb.Helper()
	provider, err := NewJWTBondingAuthProvider([]byte("performance-shared-secret"), []byte(performanceBondingSecret), 2, 0, time.Minute, 100, "", "")
	if err != nil {
		tb.Fatal(err)
	}
	return provider
}

func originalDecodeBondingHash(encoded string) (out [32]byte, valid bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(out) {
		return out, false
	}
	copy(out[:], decoded)
	return out, true
}

func TestDecodeBondingHashCompatibility(t *testing.T) {
	check := func(t *testing.T, value string) {
		t.Helper()
		want, wantValid := originalDecodeBondingHash(value)
		got, valid := decodeBondingHash(value)
		require.Equal(t, wantValid, valid, "input %q", value)
		if valid {
			assert.Equal(t, want, got, "input %q", value)
		}
	}
	for size := range 66 {
		t.Run(fmt.Sprintf("decoded-size=%d", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i*17 + 3)
			}
			value := base64.RawURLEncoding.EncodeToString(data)
			check(t, value)
			check(t, "\r\n"+value+"\r\n")
			check(t, value[:len(value)/2]+"\r\n"+value[len(value)/2:])
			check(t, value+"=")
			check(t, value+"!")
			check(t, value+"\t")
		})
	}
	// RawURLEncoding is deliberately not Strict: retain its acceptance of
	// nonzero unused bits in the final character and newlines at any boundary.
	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, last := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		check(t, canonical[:42]+string(last))
	}
	for i := 0; i <= len(canonical); i++ {
		check(t, canonical[:i]+"\r\n"+canonical[i:])
	}
}

func TestBondingHashClaimValidationCompatibility(t *testing.T) {
	provider := newPerformanceBondingProvider(t)
	device := uuid.MustParse("018dd053-54d2-7c85-a1c1-73fcd2b94da4")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("User-Agent", "compatibility reader")
	request.AddCookie(&http.Cookie{Name: "bonding-device", Value: device.String()})
	deviceHash := provider.deviceHash(device)
	agentHash := provider.agentHash(device, request)
	base := bondingJwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "session:https://example.org/session.json",
			Audience: jwt.ClaimStrings{bondingJwtAudience},
		},
		DeviceHash: base64.RawURLEncoding.EncodeToString(deviceHash[:]),
		AgentHash:  base64.RawURLEncoding.EncodeToString(agentHash[:]),
	}
	for _, test := range []struct {
		name   string
		change func(*bondingJwtClaims)
		status int
		err    string
	}{
		{"valid", func(*bondingJwtClaims) {}, 0, ""},
		{"hash-newlines", func(c *bondingJwtClaims) { c.DeviceHash += "\r\n"; c.AgentHash = "\r\n" + c.AgentHash }, 0, ""},
		{"short-device", func(c *bondingJwtClaims) { c.DeviceHash = c.DeviceHash[:42] }, http.StatusInternalServerError, "invalid device hash in JWT"},
		{"oversized-device", func(c *bondingJwtClaims) { c.DeviceHash += "A" }, http.StatusInternalServerError, "invalid device hash in JWT"},
		{"invalid-agent", func(c *bondingJwtClaims) { c.AgentHash += "!" }, http.StatusInternalServerError, "invalid agent hash in JWT"},
		{"device-mismatch", func(c *bondingJwtClaims) { c.DeviceHash = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, http.StatusForbidden, "device integrity mismatch"},
		{"agent-mismatch", func(c *bondingJwtClaims) { c.AgentHash = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, http.StatusForbidden, "browser integrity mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			test.change(&claims)
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(performanceBondingSecret))
			require.NoError(t, err)
			writer := httptest.NewRecorder()
			out, authErr := provider.Validate(writer, request, "bonding."+token)
			if test.status != 0 {
				require.NotNil(t, authErr)
				assert.Equal(t, test.status, authErr.StatusCode)
				assert.EqualError(t, authErr.Err, test.err)
				assert.Nil(t, out)
				assert.Empty(t, writer.Header().Values("Set-Cookie"))
				return
			}
			require.Nil(t, authErr)
			require.NotNil(t, out)
			assert.Equal(t, base.Subject, out.Context().Value(ContextPathKey))
			assert.Equal(t, BondingData{Key: base.Subject, Hash: agentHash, Device: device}, out.Context().Value(BondingRecordContextKey))
			cookies := writer.Result().Cookies()
			require.Len(t, cookies, 1)
			assert.Equal(t, device.String(), cookies[0].Value)
			assert.True(t, cookies[0].Secure)
			assert.True(t, cookies[0].HttpOnly)
			assert.True(t, cookies[0].Partitioned)
		})
	}
}

func BenchmarkBondingHashDecode(b *testing.B) {
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		name   string
		decode func(string) ([32]byte, bool)
	}{
		{"Original", originalDecodeBondingHash},
		{"Optimized", decodeBondingHash},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, valid := test.decode(encoded); !valid {
					b.Fatal("valid hash rejected")
				}
			}
		})
	}
}
