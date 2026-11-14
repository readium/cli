package serve

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rurl "github.com/readium/go-toolkit/pkg/util/url"
)

// BenchmarkServeColdManifestBurst measures eight simultaneous requests for the
// same uncached publication. One operation is the entire eight-request burst,
// including cache eviction, goroutine creation, and the start barrier. The
// remote variant adds 2 ms to every upstream request to model origin latency.
func BenchmarkServeColdManifestBurst(b *testing.B) {
	const concurrency = 8
	filename := filepath.Join(b.TempDir(), "benchmark.epub")
	if err := os.WriteFile(filename, streamingBenchmarkEPUB(b), 0600); err != nil {
		b.Fatal(err)
	}
	for _, remote := range []bool{false, true} {
		name := "Local/Requests8"
		if remote {
			name = "RemoteOriginDelay2ms/Requests8"
		}
		b.Run(name, func(b *testing.B) {
			var originRequests, originRanges atomic.Uint64
			conf := Remote{LocalDirectory: filepath.Dir(filename)}
			publicationURL := filepath.Base(filename)
			if remote {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					originRequests.Add(1)
					if r.Header.Get("Range") != "" {
						originRanges.Add(1)
					}
					time.Sleep(2 * time.Millisecond)
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
			target := "/webpub/" + base64.RawURLEncoding.EncodeToString([]byte(publicationURL)) + "/manifest.json"
			var requests [concurrency]*http.Request
			var writers [concurrency]streamingDiscardWriter
			for i := range requests {
				requests[i] = httptest.NewRequest(http.MethodGet, target, nil)
				requests[i].Header.Set("Accept-Encoding", "identity")
				writers[i].header = make(http.Header)
			}
			// Validate the fixture and obtain its response size outside timing.
			router.ServeHTTP(&writers[0], requests[0])
			if writers[0].status != http.StatusOK || writers[0].bytes == 0 {
				b.Fatalf("open publication: status %d, bytes %d", writers[0].status, writers[0].bytes)
			}
			wantBytes := writers[0].bytes
			b.SetBytes(concurrency * wantBytes)
			b.ReportAllocs()
			requestsBefore, rangesBefore := originRequests.Load(), originRanges.Load()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				s.lfu.Del(cacheKey)
				start := make(chan struct{})
				var ready, finished sync.WaitGroup
				ready.Add(concurrency)
				finished.Add(concurrency)
				for i := range concurrency {
					writers[i].reset()
					go func() {
						defer finished.Done()
						ready.Done()
						<-start
						router.ServeHTTP(&writers[i], requests[i])
					}()
				}
				ready.Wait()
				close(start)
				finished.Wait()
				for i := range writers {
					if writers[i].status != http.StatusOK || writers[i].bytes != wantBytes {
						b.Fatalf("request %d: status %d, bytes %d; want 200, %d", i, writers[i].status, writers[i].bytes, wantBytes)
					}
				}
			}
			b.StopTimer()
			b.ReportMetric(concurrency, "client-requests/op")
			b.ReportMetric(float64(concurrency*wantBytes), "response-bytes/op")
			if remote {
				b.ReportMetric(float64(originRequests.Load()-requestsBefore)/float64(b.N), "origin-requests/op")
				b.ReportMetric(float64(originRanges.Load()-rangesBefore)/float64(b.N), "origin-ranges/op")
			}
		})
	}
}
