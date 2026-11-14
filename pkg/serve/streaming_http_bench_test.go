package serve

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	rurl "github.com/readium/go-toolkit/pkg/util/url"
)

// BenchmarkServeHTTP includes the net/http server and client over loopback, with
// a reused client connection. Explicit encodings and disabled automatic client
// decompression ensure byte counts refer to the transferred response body.
// Optional corpus coverage is enabled by setting EPUB_BENCH_DIR.
func BenchmarkServeHTTP(b *testing.B) {
	filename := filepath.Join(b.TempDir(), "benchmark.epub")
	if err := os.WriteFile(filename, streamingBenchmarkEPUB(b), 0600); err != nil {
		b.Fatal(err)
	}
	books := []struct{ name, filename string }{{"Synthetic", filename}}
	if dir := os.Getenv("EPUB_BENCH_DIR"); dir != "" {
		books = append(books, struct{ name, filename string }{
			"MonEncyclopetitDesArts", filepath.Join(dir, "MonEncyclopetitDesArts.epub"),
		})
	}
	for _, book := range books {
		b.Run(book.name, func(b *testing.B) {
			for _, tc := range []struct {
				name, encoding string
				conditional    bool
			}{
				{name: "WarmManifest/Identity", encoding: "identity"},
				{name: "WarmManifest/Gzip", encoding: "gzip"},
				{name: "Manifest304", encoding: "identity", conditional: true},
			} {
				b.Run(tc.name, func(b *testing.B) {
					benchmarkStreamingHTTPManifest(b, book.filename, tc.encoding, tc.conditional)
				})
			}
		})
	}
}

func benchmarkStreamingHTTPManifest(b *testing.B, filename, encoding string, conditional bool) {
	if _, err := os.Stat(filename); err != nil {
		b.Fatal(err)
	}
	s := NewServer(ServerConfig{}, Remote{LocalDirectory: filepath.Dir(filename)})
	frontend := httptest.NewServer(s.Routes())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	client := &http.Client{Transport: transport}
	publicationURL := filepath.Base(filename)
	loc, err := rurl.URLFromString(publicationURL)
	if err != nil {
		frontend.Close()
		b.Fatal(err)
	}
	cacheKey := rurl.BaseFile.Resolve(loc).String()
	b.Cleanup(func() {
		transport.CloseIdleConnections()
		frontend.Close()
		s.lfu.Del(cacheKey)
	})
	target := frontend.URL + "/webpub/" + base64.RawURLEncoding.EncodeToString([]byte(publicationURL)) + "/manifest.json"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", encoding)

	// The first response opens the publication, primes its representation, and
	// establishes the client connection. A conditional case also obtains its ETag.
	response, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	wantBytes, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		b.Fatalf("prime response body: read %v, close %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusOK || wantBytes == 0 {
		b.Fatalf("prime response: status %d, bytes %d", response.StatusCode, wantBytes)
	}
	if encoding == "gzip" && response.Header.Get("Content-Encoding") != encoding {
		b.Fatalf("content encoding %q; want %q", response.Header.Get("Content-Encoding"), encoding)
	}
	wantStatus := http.StatusOK
	if conditional {
		etag := response.Header.Get("ETag")
		if etag == "" {
			b.Fatal("manifest has no ETag")
		}
		req.Header.Set("If-None-Match", etag)
		wantStatus = http.StatusNotModified
		wantBytes = 0
	}
	// Prime the exact measured request too, including the 304 branch, while
	// verifying that the HTTP connection is ready for reuse after body close.
	response, err = client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	gotBytes, readErr := io.Copy(io.Discard, response.Body)
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != wantStatus || gotBytes != wantBytes {
		b.Fatalf("warm response: status %d, bytes %d, read %v, close %v; want status %d, bytes %d", response.StatusCode, gotBytes, readErr, closeErr, wantStatus, wantBytes)
	}
	b.SetBytes(wantBytes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		gotBytes, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != wantStatus || gotBytes != wantBytes {
			b.Fatalf("response: status %d, bytes %d, read %v, close %v; want status %d, bytes %d", response.StatusCode, gotBytes, readErr, closeErr, wantStatus, wantBytes)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(wantBytes), "response-bytes/op")
}
