package serve

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/readium/cli/pkg/serve/auth"
	"github.com/readium/cli/pkg/serve/cache"
	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/archive"
	"github.com/readium/go-toolkit/pkg/fetcher"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/stretchr/testify/require"
)

type publicationSessionFetchFunc func(context.Context, string) (*session.ReadingSessionDocument, error)

func (f publicationSessionFetchFunc) Fetch(ctx context.Context, target string) (*session.ReadingSessionDocument, error) {
	return f(ctx, target)
}

// Observing Done makes concurrent tests deterministic: each waiter has reached
// either the pending-open gate or the fake upstream before the owner is released.
type publicationWaitContext struct {
	context.Context
	ready chan struct{}
	once  sync.Once
}

func (c *publicationWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.ready) })
	return c.Context.Done()
}

type publicationOpenResult struct {
	publication *cache.CachedPublication
	err         error
}

func startPublicationOpen(s *Server, ctx context.Context, key string) <-chan publicationOpenResult {
	result := make(chan publicationOpenResult, 1)
	go func() {
		publication, err := s.getPublication(context.WithValue(ctx, auth.ContextPathKey, key))
		result <- publicationOpenResult{publication, err}
	}()
	return result
}

func waitPublicationOpen(t *testing.T, results <-chan publicationOpenResult) publicationOpenResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("publication open did not finish")
		return publicationOpenResult{}
	}
}

func waitPublicationSignal(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("publication open did not reach synchronization point")
	}
}

func publicationOpenFixture(t *testing.T, padding ...int) string {
	t.Helper()
	directory := t.TempDir()
	f, err := os.Create(filepath.Join(directory, "book.epub"))
	require.NoError(t, err)
	w := zip.NewWriter(f)
	for _, entry := range []struct{ name, data string }{
		{"mimetype", "application/epub+zip"},
		{"META-INF/container.xml", `<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="package.opf" media-type="application/oebps-package+xml"/></rootfiles></container>`},
		{"package.opf", `<package xmlns="http://www.idpf.org/2007/opf" version="3.0"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Concurrent opening</dc:title><dc:language>en</dc:language></metadata><manifest><item id="chapter" href="chapter.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="chapter"/></spine></package>`},
		{"chapter.xhtml", `<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Still readable.</p></body></html>`},
	} {
		writer, err := w.Create(entry.name)
		require.NoError(t, err)
		_, err = writer.Write([]byte(entry.data))
		require.NoError(t, err)
	}
	if len(padding) > 0 {
		writer, err := w.CreateHeader(&zip.FileHeader{Name: "padding.bin", Method: zip.Store})
		require.NoError(t, err)
		_, err = writer.Write(make([]byte, padding[0]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
	return directory
}

func publicationSessionDocument() *session.ReadingSessionDocument {
	return &session.ReadingSessionDocument{Links: manifest.LinkList{{
		Href: manifest.MustNewHREFFromString("file:///book.epub", false), Rels: manifest.Strings{"publication"},
	}}}
}

func TestPublicationOpenCoalescesAndRetainsEachReader(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 16)
	proceed := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	s := NewServer(ServerConfig{ReadingSessionFetcher: publicationSessionFetchFunc(func(ctx context.Context, _ string) (*session.ReadingSessionDocument, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-proceed:
			return publicationSessionDocument(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})}, Remote{LocalDirectory: publicationOpenFixture(t)})
	const key = "session:https://example.org/session"
	results := []<-chan publicationOpenResult{startPublicationOpen(s, t.Context(), key)}
	waitPublicationSignal(t, entered)
	for range 8 {
		ctx := &publicationWaitContext{Context: t.Context(), ready: make(chan struct{})}
		results = append(results, startPublicationOpen(s, ctx, key))
		waitPublicationSignal(t, ctx.ready)
	}
	require.Equal(t, int32(1), calls.Load(), "only the owner fetches and opens the publication")
	unblock.Do(func() { close(proceed) })
	var publications []*cache.CachedPublication
	for _, result := range results {
		r := waitPublicationOpen(t, result)
		require.NoError(t, r.err)
		require.NotNil(t, r.publication)
		publications = append(publications, r.publication)
	}
	for _, p := range publications[1:] {
		require.Same(t, publications[0], p)
	}
	// Eviction must not close the file while any coalesced request holds it.
	s.lfu.Del(key)
	for _, p := range publications {
		resource := p.Get(t.Context(), p.Manifest.ReadingOrder[0])
		text, err := fetcher.ReadResourceAsString(t.Context(), resource)
		resource.Close()
		require.Nil(t, err)
		require.Contains(t, text, "Still readable.")
		p.Release()
	}
	require.False(t, publications[0].Retain(), "last release closes the evicted publication")
}

func TestPublicationOpenWaitingCancellationDoesNotCancelOwner(t *testing.T) {
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	var calls atomic.Int32
	s := NewServer(ServerConfig{ReadingSessionFetcher: publicationSessionFetchFunc(func(ctx context.Context, _ string) (*session.ReadingSessionDocument, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-proceed:
			return publicationSessionDocument(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})}, Remote{LocalDirectory: publicationOpenFixture(t)})
	const key = "session:https://example.org/session"
	owner := startPublicationOpen(s, t.Context(), key)
	waitPublicationSignal(t, entered)
	waitCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &publicationWaitContext{Context: waitCtx, ready: make(chan struct{})}
	waiter := startPublicationOpen(s, ctx, key)
	waitPublicationSignal(t, ctx.ready)
	cancel()
	require.ErrorIs(t, waitPublicationOpen(t, waiter).err, context.Canceled)
	require.Equal(t, int32(1), calls.Load())
	unblock.Do(func() { close(proceed) })
	result := waitPublicationOpen(t, owner)
	require.NoError(t, result.err)
	result.publication.Release()
	s.lfu.Del(key)
}

func TestPublicationOpenFailureDoesNotPoisonRetry(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "upstreamError", true: "ownerCanceled"}[cancelOwner], func(t *testing.T) {
			var calls atomic.Int32
			entered := make(chan struct{})
			s := NewServer(ServerConfig{ReadingSessionFetcher: publicationSessionFetchFunc(func(ctx context.Context, _ string) (*session.ReadingSessionDocument, error) {
				if calls.Add(1) == 1 {
					close(entered)
					if cancelOwner {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return nil, errors.New("upstream unavailable")
				}
				return publicationSessionDocument(), nil
			})}, Remote{LocalDirectory: publicationOpenFixture(t)})
			const key = "session:https://example.org/session"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			owner := startPublicationOpen(s, ctx, key)
			waitPublicationSignal(t, entered)
			retry := startPublicationOpen(s, t.Context(), key)
			cancel()
			require.Error(t, waitPublicationOpen(t, owner).err)
			result := waitPublicationOpen(t, retry)
			require.NoError(t, result.err)
			require.Equal(t, int32(2), calls.Load())
			result.publication.Release()
			s.lfu.Del(key)
		})
	}
}

func TestPublicationOpenDifferentKeysProceedIndependently(t *testing.T) {
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	s := NewServer(ServerConfig{ReadingSessionFetcher: publicationSessionFetchFunc(func(ctx context.Context, _ string) (*session.ReadingSessionDocument, error) {
		entered <- struct{}{}
		select {
		case <-proceed:
			return publicationSessionDocument(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})}, Remote{LocalDirectory: publicationOpenFixture(t)})
	first := startPublicationOpen(s, t.Context(), "session:https://example.org/first")
	second := startPublicationOpen(s, t.Context(), "session:https://example.org/second")
	waitPublicationSignal(t, entered)
	waitPublicationSignal(t, entered)
	unblock.Do(func() { close(proceed) })
	for _, result := range []<-chan publicationOpenResult{first, second} {
		r := waitPublicationOpen(t, result)
		require.NoError(t, r.err)
		r.publication.Release()
	}
	s.lfu.Del("session:https://example.org/first")
	s.lfu.Del("session:https://example.org/second")
}

type publicationOriginRoundTripper func(*http.Request) (*http.Response, error)

func (f publicationOriginRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPublicationOpenHonorsRemoteArchiveConfig(t *testing.T) {
	// A ZIP larger than the central-directory tail but smaller than the default
	// whole-archive threshold distinguishes the two caching strategies.
	directory := publicationOpenFixture(t, 128<<10)
	data, err := os.ReadFile(filepath.Join(directory, "book.epub"))
	require.NoError(t, err)
	custom := archive.NewDefaultRemoteArchiveConfig()
	custom.CacheAllThreshold = 1
	var counts []int
	for _, config := range []archive.RemoteArchiveConfig{{}, custom} {
		gets := 0
		client := &http.Client{Transport: publicationOriginRoundTripper(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet {
				gets++
			}
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/epub+zip")
			http.ServeContent(recorder, req, "book.epub", time.Unix(1700000000, 0), bytes.NewReader(data))
			return recorder.Result(), nil
		})}
		s := NewServer(ServerConfig{}, Remote{HTTP: client, HTTPSEnabled: true, Config: config})
		const target = "https://example.org/book.epub"
		publication, err := s.getPublication(context.WithValue(t.Context(), auth.ContextPathKey, target))
		require.NoError(t, err)
		publication.Release()
		s.lfu.Del(target)
		counts = append(counts, gets)
	}
	require.Equal(t, 1, counts[0], "zero configuration retains toolkit whole-archive caching defaults")
	require.Greater(t, counts[1], counts[0], "custom threshold must select range retrieval instead of fetching the whole ZIP")
}

func TestPublicationOpenWaiterStillEnforcesDeviceLimit(t *testing.T) {
	provider, err := auth.NewJWTBondingAuthProvider(make([]byte, 32), make([]byte, 32), 1, 4, time.Hour, 128, "reader", "")
	require.NoError(t, err)
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	var calls atomic.Int32
	s := NewServer(ServerConfig{
		Auth: provider,
		ReadingSessionFetcher: publicationSessionFetchFunc(func(ctx context.Context, _ string) (*session.ReadingSessionDocument, error) {
			calls.Add(1)
			entered <- struct{}{}
			select {
			case <-proceed:
				document := publicationSessionDocument()
				// Decoding sets the refresh timestamp as a real session fetch does.
				err := json.Unmarshal([]byte(`{"status":"ready","devices":1}`), &document.Rights)
				return document, err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	}, Remote{LocalDirectory: publicationOpenFixture(t)})
	const key = "session:https://example.org/session"
	firstContext := context.WithValue(t.Context(), auth.BondingRecordContextKey, auth.BondingData{Key: "reader", Device: uuid.New()})
	owner := startPublicationOpen(s, firstContext, key)
	waitPublicationSignal(t, entered)
	secondContext := context.WithValue(t.Context(), auth.BondingRecordContextKey, auth.BondingData{Key: "reader", Device: uuid.New()})
	waitContext := &publicationWaitContext{Context: secondContext, ready: make(chan struct{})}
	waiter := startPublicationOpen(s, waitContext, key)
	waitPublicationSignal(t, waitContext.ready)
	unblock.Do(func() { close(proceed) })
	first := waitPublicationOpen(t, owner)
	require.NoError(t, first.err)
	second := waitPublicationOpen(t, waiter)
	require.Error(t, second.err, "sharing the publication open must not share the first reader's device authorization")
	require.Nil(t, second.publication)
	require.Equal(t, int32(1), calls.Load())
	first.publication.Release()
	s.lfu.Del(key)
}
