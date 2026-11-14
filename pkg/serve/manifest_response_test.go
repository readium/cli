package serve

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/readium/cli/pkg/serve/auth"
	"github.com/stretchr/testify/require"
)

type manifestTestAuth struct {
	delegate auth.AuthProvider
	denied   bool
	calls    int
}

func (a *manifestTestAuth) Validate(w http.ResponseWriter, r *http.Request, token string) (*http.Request, *auth.AuthError) {
	a.calls++
	if a.denied {
		return nil, &auth.AuthError{StatusCode: http.StatusForbidden, Err: errors.New("access revoked")}
	}
	return a.delegate.Validate(w, r, token)
}

func TestManifestResponseHTTP(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "book.cbz"), buildCBZ(t, pattern(4096)), 0600))
	a := &manifestTestAuth{delegate: auth.NewB64EncodedAuthProvider()}
	s := NewServer(ServerConfig{Auth: a}, Remote{LocalDirectory: dir})
	router := s.Routes()
	endpoint := "/webpub/" + fileToken("book.cbz") + "/manifest.json"
	request := func(method, encoding, etag, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, endpoint, nil)
		req.Host = host
		if encoding != "" {
			req.Header.Set("Accept-Encoding", encoding)
		}
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	identity := request(http.MethodGet, "", "", "one.example")
	require.Equal(t, http.StatusOK, identity.Code)
	require.Contains(t, identity.Body.String(), "http://one.example")
	for _, encoding := range []string{"gzip", "br"} {
		for range 2 {
			compressed := request(http.MethodGet, encoding, "", "one.example")
			require.Equal(t, http.StatusOK, compressed.Code)
			require.Equal(t, encoding, compressed.Header().Get("Content-Encoding"))
			var reader io.Reader
			if encoding == "gzip" {
				r, err := gzip.NewReader(compressed.Body)
				require.NoError(t, err)
				defer r.Close()
				reader = r
			} else {
				reader = brotli.NewReader(compressed.Body)
			}
			data, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, identity.Body.Bytes(), data)
		}
	}
	conditional := request(http.MethodGet, "", identity.Header().Get("ETag"), "one.example")
	require.Equal(t, http.StatusNotModified, conditional.Code)
	require.Empty(t, conditional.Body.Bytes())
	head := request(http.MethodHead, "", "", "one.example")
	require.Equal(t, http.StatusOK, head.Code)
	require.Empty(t, head.Body.Bytes())
	require.Equal(t, identity.Header().Get("ETag"), head.Header().Get("ETag"))
	other := request(http.MethodGet, "", identity.Header().Get("ETag"), "two.example")
	require.Equal(t, http.StatusOK, other.Code)
	require.Contains(t, other.Body.String(), "http://two.example")
	require.NotEqual(t, identity.Header().Get("ETag"), other.Header().Get("ETag"))
	require.False(t, bytes.Equal(identity.Body.Bytes(), other.Body.Bytes()))
	calls := a.calls
	a.denied = true
	denied := request(http.MethodGet, "", other.Header().Get("ETag"), "two.example")
	require.Equal(t, http.StatusForbidden, denied.Code, "cached representations must still require authorization")
	require.Equal(t, calls+1, a.calls)
}

func TestEncodedRequestsPreserveAssetRanges(t *testing.T) {
	payload := pattern(2 << 20)
	book := buildCBZ(t, payload)
	for _, remote := range []bool{false, true} {
		name := "Local"
		if remote {
			name = "Remote"
		}
		t.Run(name, func(t *testing.T) {
			var router http.Handler
			var token string
			if remote {
				o := newOrigin(map[string][]byte{"/book.cbz": book})
				defer o.srv.Close()
				router = newTestRouter(t, o)
				token = pubToken(o, "/book.cbz")
			} else {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "book.cbz"), book, 0600))
				router = newFileTestRouter(t, dir)
				token = fileToken("book.cbz")
			}
			endpoint := "/webpub/" + token + "/001.jpg"
			for _, encoding := range []string{"gzip", "br", "gzip, deflate, br, zstd"} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					req := httptest.NewRequest(method, endpoint, nil)
					req.Header.Set("Accept-Encoding", encoding)
					req.Header.Set("Range", "bytes=1048576-1114111")
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					require.Equal(t, http.StatusPartialContent, rec.Code)
					require.Equal(t, "bytes 1048576-1114111/2097152", rec.Header().Get("Content-Range"))
					require.Equal(t, "65536", rec.Header().Get("Content-Length"))
					require.Empty(t, rec.Header().Get("Content-Encoding"))
					if method == http.MethodHead {
						require.Empty(t, rec.Body.Bytes())
					} else {
						require.Equal(t, payload[1048576:1114112], rec.Body.Bytes())
					}
				}
			}
		})
	}
}
