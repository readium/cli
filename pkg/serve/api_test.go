package serve

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain discards slog output: handlers log every failed publication open,
// and the confinement/error-path tests trigger those on purpose.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// originRequest records one request that reached the fake remote origin.
type originRequest struct {
	method string
	path   string
	rng    string // Range header
}

// origin is a fake remote HTTP storage backend: it serves in-memory files with
// byte-range support and records every request, so tests can assert how the
// publication server fetches from a remote source.
type origin struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []originRequest
	srv      *httptest.Server
}

func newOrigin(files map[string][]byte) *origin {
	o := &origin{files: files}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.requests = append(o.requests, originRequest{method: r.Method, path: r.URL.Path, rng: r.Header.Get("Range")})
		data, ok := o.files[r.URL.Path]
		o.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, r.URL.Path, time.Unix(1700000000, 0), bytes.NewReader(data))
	}))
	return o
}

func (o *origin) reset() {
	o.mu.Lock()
	o.requests = nil
	o.mu.Unlock()
}

// snapshot returns the recorded requests for a given file path.
func (o *origin) snapshot(path string) []originRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]originRequest, 0, len(o.requests))
	for _, r := range o.requests {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

// splitByMethod separates recorded origin requests into GETs and the rest.
func splitByMethod(reqs []originRequest) (gets, others []originRequest) {
	for _, r := range reqs {
		if r.method == http.MethodGet {
			gets = append(gets, r)
		} else {
			others = append(others, r)
		}
	}
	return
}

// pattern returns pseudo-random but deterministic content of the given size.
func pattern(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte((i*31 + i/251) % 256)
	}
	return data
}

func newTestRouter(t *testing.T, o *origin) http.Handler {
	t.Helper()
	s := NewServer(ServerConfig{
		AudioParsingCacheRetain: true, // the CLI default
	}, Remote{
		HTTP:        o.srv.Client(),
		HTTPEnabled: true,
	})
	return s.Routes()
}

func pubToken(o *origin, path string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(o.srv.URL + path))
}

// openPublication fetches the manifest (which parses and caches the
// publication) and returns the href of the first reading order item.
func openPublication(t *testing.T, router http.Handler, token string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/manifest.json", nil))
	require.Equal(t, http.StatusOK, rec.Code, "manifest request failed: %s", rec.Body.String())

	var m struct {
		ReadingOrder []struct {
			Href string `json:"href"`
		} `json:"readingOrder"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
	require.NotEmpty(t, m.ReadingOrder)
	return strings.TrimPrefix(m.ReadingOrder[0].Href, "/")
}

// readingSessionDataURL must recover the underlying data URL from a
// `session:<url>` value: net/url parses the part after the scheme as opaque and
// splits any query off into RawQuery, so the query has to be reattached while
// the fragment is dropped (fragments are client-only and never fetched).
func TestReadingSessionDataURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "no query",
			in:   "session:https://example.com/data.json",
			want: "https://example.com/data.json",
		},
		{
			name: "query preserved",
			in:   "session:https://example.com/data.json?token=abc&x=1",
			want: "https://example.com/data.json?token=abc&x=1",
		},
		{
			name: "fragment dropped",
			in:   "session:https://example.com/data.json#frag",
			want: "https://example.com/data.json",
		},
		{
			name: "query kept, fragment dropped",
			in:   "session:https://example.com/data.json?token=abc#frag",
			want: "https://example.com/data.json?token=abc",
		},
		{
			name: "forced empty query preserved",
			in:   "session:https://example.com/data.json?",
			want: "https://example.com/data.json?",
		},
		{
			name:    "missing data (opaque only scheme)",
			in:      "session:",
			wantErr: true,
		},
		{
			name:    "missing data (hierarchical form)",
			in:      "session://example.com/data.json",
			wantErr: true,
		},
		{
			name:    "unparseable",
			in:      "session:\x7f",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readingSessionDataURL(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A ranged request for a bare remote file must be served with a single,
// equally-ranged origin request whose body is streamed through — not a
// buffered read of the whole remaining file.
func TestServeRemoteBareFileRanged(t *testing.T) {
	payload := pattern(4 << 20)
	o := newOrigin(map[string][]byte{"/audio/book.mp3": payload})
	defer o.srv.Close()
	router := newTestRouter(t, o)

	token := pubToken(o, "/audio/book.mp3")
	href := openPublication(t, router, token)
	o.reset()

	// Open-ended range, the shape browsers use for media
	req := httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/"+href, nil)
	req.Header.Set("Range", "bytes=1048576-")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Equal(t, fmt.Sprintf("bytes 1048576-%d/%d", len(payload)-1, len(payload)), rec.Header().Get("Content-Range"))
	assert.Equal(t, payload[1048576:], rec.Body.Bytes())

	// Exactly one origin GET, ranged like the client's request. At most one
	// metadata HEAD for the content-length header may accompany it (none once
	// the toolkit dependency shares resource sizes across requests).
	gets, heads := splitByMethod(o.snapshot("/audio/book.mp3"))
	require.Len(t, gets, 1, "a ranged asset request must map to exactly one origin GET, got %+v", gets)
	assert.Equal(t, fmt.Sprintf("bytes=1048576-%d", len(payload)-1), gets[0].rng)
	assert.LessOrEqual(t, len(heads), 1, "at most one metadata HEAD per asset request, got %+v", heads)
}

// A full (un-ranged) request for a bare remote file serves the header region
// retained from parsing out of memory and streams the remainder from a single
// ranged origin request.
func TestServeRemoteBareFileFull(t *testing.T) {
	payload := pattern(2 << 20)
	o := newOrigin(map[string][]byte{"/audio/book.mp3": payload})
	defer o.srv.Close()
	router := newTestRouter(t, o)

	token := pubToken(o, "/audio/book.mp3")
	href := openPublication(t, router, token)
	o.reset()

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/"+href, nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, payload, rec.Body.Bytes())

	gets, heads := splitByMethod(o.snapshot("/audio/book.mp3"))
	require.Len(t, gets, 1, "a full asset request must map to exactly one origin GET, got %+v", gets)
	assert.Regexp(t, `^$|^bytes=\d+-2097151$`, gets[0].rng,
		"the origin GET must cover (at most) the part after the retained parse cache")
	assert.LessOrEqual(t, len(heads), 1, "at most one metadata HEAD per asset request, got %+v", heads)
}

// Requests inside the region retained from parsing (the file header a browser
// reads first) are served entirely from memory: no origin request at all.
func TestServeRemoteBareFileCachedRegion(t *testing.T) {
	payload := pattern(2 << 20)
	o := newOrigin(map[string][]byte{"/audio/book.mp3": payload})
	defer o.srv.Close()
	router := newTestRouter(t, o)

	token := pubToken(o, "/audio/book.mp3")
	href := openPublication(t, router, token)
	o.reset()

	req := httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/"+href, nil)
	req.Header.Set("Range", "bytes=0-65535")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Equal(t, payload[:65536], rec.Body.Bytes())
	assert.Empty(t, o.snapshot("/audio/book.mp3"),
		"a range inside the retained parse cache must not touch the origin")
}

// buildCBZ builds an in-memory comic book archive with a large stored entry.
func buildCBZ(t *testing.T, big []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "001.jpg", Method: zip.Store})
	require.NoError(t, err)
	_, err = w.Write(big)
	require.NoError(t, err)
	w, err = zw.CreateHeader(&zip.FileHeader{Name: "002.jpg", Method: zip.Store})
	require.NoError(t, err)
	_, err = w.Write(pattern(2048))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// A ranged request for a stored entry inside a remote archive must transfer
// only (roughly) the requested range from the origin, in large chunks — not
// the entry's prefix, and not the whole remaining archive.
func TestServeRemoteArchiveStoredEntryRanged(t *testing.T) {
	big := pattern(5 << 20)
	o := newOrigin(map[string][]byte{"/pub/book.cbz": buildCBZ(t, big)})
	defer o.srv.Close()
	router := newTestRouter(t, o)

	token := pubToken(o, "/pub/book.cbz")
	openPublication(t, router, token)
	o.reset()

	// 3 MiB range starting 1 MiB into the entry
	req := httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/001.jpg", nil)
	req.Header.Set("Range", "bytes=1048576-4194303")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusPartialContent, rec.Code)
	require.Equal(t, big[1048576:4194304], rec.Body.Bytes())

	// Expected origin traffic: at most one (open-ended, but aborted) header
	// probe for the entry, plus the body fetched in copy-buffer-sized chunks
	// (2 MiB + 1 MiB for a 3 MiB range). Before the fix this was one buffered
	// read of the whole remaining entry plus a full drain of the archive tail.
	reqs := o.snapshot("/pub/book.cbz")
	var bounded, openEnded int
	for _, r := range reqs {
		if strings.HasSuffix(r.rng, "-") {
			openEnded++
		} else {
			bounded++
		}
	}
	assert.LessOrEqual(t, openEnded, 1, "at most the header probe may be open-ended, got %+v", reqs)
	assert.LessOrEqual(t, bounded, 2, "3 MiB should be fetched in at most two chunks, got %+v", reqs)

	// A second ranged request must not re-fetch the entry header.
	o.reset()
	req = httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/001.jpg", nil)
	req.Header.Set("Range", "bytes=0-2097151")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusPartialContent, rec.Code)
	require.Equal(t, big[:2097152], rec.Body.Bytes())
	for _, r := range o.snapshot("/pub/book.cbz") {
		assert.False(t, strings.HasSuffix(r.rng, "-"), "entry header should be cached, got open-ended request %+v", r)
	}
}

// newFileTestRouter serves publications from a local directory with the file
// scheme enabled and the default (base64url) auth.
func newFileTestRouter(t *testing.T, dir string) http.Handler {
	t.Helper()
	s := NewServer(ServerConfig{}, Remote{LocalDirectory: dir})
	return s.Routes()
}

func fileToken(path string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(path))
}

// TestServeLocalFileConfinement checks that requests for the file scheme cannot
// escape --file-directory, including via a symlink inside the directory that
// points outside it — the case a purely lexical containment check misses and
// os.Root rejects.
func TestServeLocalFileConfinement(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "inside")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(inside, 0o755))
	require.NoError(t, os.MkdirAll(outside, 0o755))

	pub := buildCBZ(t, pattern(4096))
	require.NoError(t, os.WriteFile(filepath.Join(inside, "book.cbz"), pub, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.cbz"), pub, 0o644))

	router := newFileTestRouter(t, inside)

	get := func(token string) int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webpub/"+token+"/manifest.json", nil))
		return rec.Code
	}

	// Positive control: a real publication inside the directory is served.
	require.Equal(t, http.StatusOK, get(fileToken("book.cbz")),
		"a publication inside the file directory must be served")

	// Parent-directory traversal must not reach the sibling publication.
	assert.Equal(t, http.StatusNotFound, get(fileToken("../outside/secret.cbz")),
		"a ../ traversal must not escape the file directory")

	// A symlink inside the directory that points outside it must not be
	// followed out of the directory. This is the escape a lexical prefix check
	// would allow and os.Root blocks.
	if runtime.GOOS != "windows" {
		link := filepath.Join(inside, "escape.cbz")
		require.NoError(t, os.Symlink(filepath.Join(outside, "secret.cbz"), link))
		assert.Equal(t, http.StatusNotFound, get(fileToken("escape.cbz")),
			"a symlink escaping the file directory must not be served")
	}
}
