package serve

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	rurl "github.com/readium/go-toolkit/pkg/util/url"
)

// BenchmarkServeSynthetic exercises the complete router with a reproducible EPUB.
// The response writer discards bodies so allocations measure serving, rather than
// retaining responses. Remote requests use a real HTTP origin with range support.
func BenchmarkServeSynthetic(b *testing.B) {
	filename := filepath.Join(b.TempDir(), "benchmark.epub")
	if err := os.WriteFile(filename, streamingBenchmarkEPUB(b), 0600); err != nil {
		b.Fatal(err)
	}
	benchmarkStreamingBook(b, filename, true)
}

// BenchmarkServeCorpus is optional: point EPUB_BENCH_DIR at publications/dm.
// These books cover a large manifest and a long reading order, respectively.
func BenchmarkServeCorpus(b *testing.B) {
	dir := os.Getenv("EPUB_BENCH_DIR")
	if dir == "" {
		b.Skip("set EPUB_BENCH_DIR to a local EPUB corpus directory")
	}
	for _, name := range []string{"MonEncyclopetitDesArts.epub", "moby-dick.epub"} {
		b.Run(strings.TrimSuffix(name, ".epub"), func(b *testing.B) {
			filename := filepath.Join(dir, name)
			if _, err := os.Stat(filename); err != nil {
				b.Fatal(err)
			}
			benchmarkStreamingBook(b, filename, false)
		})
	}
}

type streamingBenchmarkCase struct {
	name, href, encoding, byteRange string
	conditional, cold               bool
}

func benchmarkStreamingBook(b *testing.B, filename string, synthetic bool) {
	for _, remote := range []bool{false, true} {
		name := "Local"
		if remote {
			name = "Remote"
		}
		b.Run(name, func(b *testing.B) {
			cases := []streamingBenchmarkCase{
				{name: "WarmManifest/Identity", encoding: "identity"},
				{name: "WarmManifest/Gzip", encoding: "gzip"},
				{name: "WarmManifest/Brotli", encoding: "br"},
				{name: "Manifest304", encoding: "identity", conditional: true},
				{name: "ColdManifest", encoding: "identity", cold: true},
				{name: "LateChapter/Identity", href: "@last-chapter", encoding: "identity"},
				{name: "LateChapter/Gzip", href: "@last-chapter", encoding: "gzip"},
			}
			if synthetic {
				cases = append(cases,
					streamingBenchmarkCase{name: "StoredChapter/Identity", href: "OPS/stored.xhtml", encoding: "identity"},
					streamingBenchmarkCase{name: "StoredChapter/Gzip", href: "OPS/stored.xhtml", encoding: "gzip"},
					streamingBenchmarkCase{name: "StoredRange", href: "OPS/large.bin", encoding: "identity", byteRange: "bytes=1048576-1114111"},
				)
			}
			for _, tc := range cases {
				b.Run(tc.name, func(b *testing.B) {
					benchmarkStreamingRequest(b, filename, remote, tc)
				})
			}
		})
	}
}

func benchmarkStreamingRequest(b *testing.B, filename string, remote bool, tc streamingBenchmarkCase) {
	var originRequests, originRanges atomic.Uint64
	conf := Remote{LocalDirectory: filepath.Dir(filename)}
	publicationURL := filepath.Base(filename)
	if remote {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originRequests.Add(1)
			if r.Header.Get("Range") != "" {
				originRanges.Add(1)
			}
			f, err := os.Open(filename)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer f.Close()
			w.Header().Set("Content-Type", "application/epub+zip")
			http.ServeContent(w, r, filepath.Base(filename), time.Unix(1700000000, 0), f)
		}))
		b.Cleanup(origin.Close)
		conf = Remote{HTTP: origin.Client(), HTTPEnabled: true}
		publicationURL = origin.URL + "/book.epub"
	}
	s := NewServer(ServerConfig{}, conf)
	router := s.Routes()
	loc, err := rurl.URLFromString(publicationURL)
	if err != nil {
		b.Fatal(err)
	}
	cacheKey := rurl.BaseFile.Resolve(loc).String()
	b.Cleanup(func() { s.lfu.Del(cacheKey) })
	prefix := "/webpub/" + base64.RawURLEncoding.EncodeToString([]byte(publicationURL)) + "/"
	manifestRequest := httptest.NewRequest(http.MethodGet, prefix+"manifest.json", nil)
	manifestRequest.Header.Set("Accept-Encoding", "identity")
	manifestResponse := httptest.NewRecorder()
	router.ServeHTTP(manifestResponse, manifestRequest)
	if manifestResponse.Code != http.StatusOK {
		b.Fatalf("open publication: status %d: %s", manifestResponse.Code, manifestResponse.Body.String())
	}
	href := tc.href
	if href == "@last-chapter" {
		var manifest struct {
			ReadingOrder []struct {
				Href string `json:"href"`
				Type string `json:"type"`
			} `json:"readingOrder"`
		}
		if err := json.Unmarshal(manifestResponse.Body.Bytes(), &manifest); err != nil {
			b.Fatal(err)
		}
		href = ""
		for i := len(manifest.ReadingOrder) - 1; i >= 0; i-- {
			link := manifest.ReadingOrder[i]
			if link.Type == "application/xhtml+xml" || link.Type == "text/html" {
				href = link.Href
				break
			}
		}
		if href == "" {
			b.Fatal("publication has no HTML reading-order resource")
		}
	}
	target := prefix + "manifest.json"
	if href != "" {
		resourceURL, err := url.Parse(href)
		if err != nil {
			b.Fatal(err)
		}
		target = prefix + strings.TrimPrefix(resourceURL.EscapedPath(), "/")
		if resourceURL.RawQuery != "" {
			target += "?" + resourceURL.RawQuery
		}
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept-Encoding", tc.encoding)
	if tc.byteRange != "" {
		req.Header.Set("Range", tc.byteRange)
	}
	if tc.conditional {
		etag := manifestResponse.Header().Get("ETag")
		if etag == "" {
			b.Fatal("manifest has no ETag")
		}
		req.Header.Set("If-None-Match", etag)
	}
	wantStatus := http.StatusOK
	if tc.conditional {
		wantStatus = http.StatusNotModified
	} else if tc.byteRange != "" {
		wantStatus = http.StatusPartialContent
	}
	w := &streamingDiscardWriter{header: make(http.Header)}
	router.ServeHTTP(w, req)
	if w.status != wantStatus || (wantStatus != http.StatusNotModified && w.bytes == 0) {
		b.Fatalf("warm request: status %d, bytes %d; want status %d", w.status, w.bytes, wantStatus)
	}
	if tc.conditional && w.bytes != 0 {
		b.Fatalf("304 response contains %d body bytes", w.bytes)
	}
	if tc.encoding != "identity" && w.header.Get("Content-Encoding") != tc.encoding {
		b.Fatalf("content encoding %q; want %q", w.header.Get("Content-Encoding"), tc.encoding)
	}
	wantBytes := w.bytes
	b.SetBytes(wantBytes)
	b.ReportAllocs()
	requestsBefore, rangesBefore := originRequests.Load(), originRanges.Load()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if tc.cold {
			// Include eviction/close: each operation opens and serves afresh.
			s.lfu.Del(cacheKey)
		}
		w.reset()
		router.ServeHTTP(w, req)
		if w.status != wantStatus || w.bytes != wantBytes {
			b.Fatalf("status %d, bytes %d; want %d, %d", w.status, w.bytes, wantStatus, wantBytes)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(wantBytes), "response-bytes/op")
	if remote {
		b.ReportMetric(float64(originRequests.Load()-requestsBefore)/float64(b.N), "origin-requests/op")
		b.ReportMetric(float64(originRanges.Load()-rangesBefore)/float64(b.N), "origin-ranges/op")
	}
}

type streamingDiscardWriter struct {
	header http.Header
	status int
	bytes  int64
}

func (w *streamingDiscardWriter) Header() http.Header { return w.header }
func (w *streamingDiscardWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *streamingDiscardWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += int64(len(p))
	return len(p), nil
}
func (w *streamingDiscardWriter) reset() {
	clear(w.header)
	w.status = 0
	w.bytes = 0
}

func streamingBenchmarkEPUB(tb testing.TB) []byte {
	tb.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	add := func(name string, method uint16, data []byte) {
		packed := data
		if method == zip.Deflate {
			var compressed bytes.Buffer
			fw, err := flate.NewWriter(&compressed, flate.DefaultCompression)
			if err != nil {
				tb.Fatal(err)
			}
			if _, err := fw.Write(data); err != nil {
				tb.Fatal(err)
			}
			if err := fw.Close(); err != nil {
				tb.Fatal(err)
			}
			packed = compressed.Bytes()
		}
		// Include sizes in local headers, as typical EPUB authoring tools do.
		w, err := zw.CreateRaw(&zip.FileHeader{Name: name, Method: method,
			CRC32: crc32.ChecksumIEEE(data), CompressedSize64: uint64(len(packed)), UncompressedSize64: uint64(len(data))})
		if err != nil {
			tb.Fatal(err)
		}
		if _, err := w.Write(packed); err != nil {
			tb.Fatal(err)
		}
	}
	add("mimetype", zip.Store, []byte("application/epub+zip"))
	add("META-INF/container.xml", zip.Deflate, []byte(`<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OPS/package.opf" media-type="application/oebps-package+xml"/></rootfiles></container>`))
	var items, spine strings.Builder
	for i := 0; i < 128; i++ {
		name := fmt.Sprintf("chapter-%03d.xhtml", i)
		fmt.Fprintf(&items, `<item id="c%d" href="%s" media-type="application/xhtml+xml"/>`, i, name)
		fmt.Fprintf(&spine, `<itemref idref="c%d"/>`, i)
		add("OPS/"+name, zip.Deflate, []byte(`<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>Chapter</title></head><body><p>A short chapter.</p></body></html>`))
	}
	items.WriteString(`<item id="stored" href="stored.xhtml" media-type="application/xhtml+xml"/><item id="deflated" href="deflated.xhtml" media-type="application/xhtml+xml"/><item id="large" href="large.bin" media-type="application/octet-stream"/><item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>`)
	spine.WriteString(`<itemref idref="stored"/><itemref idref="deflated"/>`)
	opf := `<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="uid"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="uid">urn:benchmark:streaming</dc:identifier><dc:title>HTTP streaming benchmark</dc:title><dc:language>en</dc:language><meta property="dcterms:modified">2020-01-01T00:00:00Z</meta></metadata><manifest>` + items.String() + `</manifest><spine>` + spine.String() + `</spine></package>`
	add("OPS/package.opf", zip.Deflate, []byte(opf))
	add("OPS/nav.xhtml", zip.Deflate, []byte(`<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><head><title>Contents</title></head><body><nav epub:type="toc"><ol><li><a href="stored.xhtml">Stored</a></li><li><a href="deflated.xhtml">Deflated</a></li></ol></nav></body></html>`))
	chapter := []byte(`<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>Chapter</title></head><body>` + strings.Repeat(`<p>A paragraph with Unicode: café, 日本語, and a little repeated text.</p>`, 1024) + `</body></html>`)
	add("OPS/stored.xhtml", zip.Store, chapter)
	add("OPS/deflated.xhtml", zip.Deflate, chapter)
	// Exceed the remote archive's small-file cache and exercise actual ranges.
	large := make([]byte, 2<<20)
	for i := range large {
		large[i] = byte(i * 31)
	}
	add("OPS/large.bin", zip.Store, large)
	if err := zw.Close(); err != nil {
		tb.Fatal(err)
	}
	return out.Bytes()
}
