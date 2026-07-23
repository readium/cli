package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	nurl "net/url"

	"github.com/gorilla/mux"
	httprange "github.com/gotd/contrib/http_range"
	"github.com/maypok86/otter/v2"
	"github.com/readium/cli/pkg/serve/auth"
	"github.com/readium/cli/pkg/serve/cache"
	"github.com/readium/cli/pkg/serve/problems"
	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/archive"
	"github.com/readium/go-toolkit/pkg/asset"
	"github.com/readium/go-toolkit/pkg/fetcher"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/parser"
	"github.com/readium/go-toolkit/pkg/parser/audio"
	"github.com/readium/go-toolkit/pkg/parser/epub"
	"github.com/readium/go-toolkit/pkg/parser/image"
	"github.com/readium/go-toolkit/pkg/parser/pdf"
	"github.com/readium/go-toolkit/pkg/parser/webpub"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/zeebo/xxh3"
)

func readingSessionDataURL(sessionURL string) (string, error) {
	cloc, err := nurl.Parse(sessionURL)
	if err != nil {
		return "", err
	}
	// Example: session:https://example.com/data.json?t=abc --> https://example.com/data.json?t=abc
	if cloc.Opaque == "" {
		return "", errors.New("reading session URL is missing data")
	}
	target := cloc.Opaque
	if cloc.ForceQuery || cloc.RawQuery != "" {
		target += "?" + cloc.RawQuery
	}
	return target, nil
}

func (s *Server) getPublication(ctx context.Context) (*cache.CachedPublication, error) {
	filename, ok := ctx.Value(auth.ContextPathKey).(string)
	if !ok {
		return nil, problems.Internal("missing publication path in context", nil)
	}

	isSession := strings.HasPrefix(filename, session.SchemeReadingSession+":")
	_, bapok := s.config.Auth.(auth.BondingAuthProvider)
	var u url.AbsoluteURL
	var cacheKey string
	if isSession {
		// Reading session (`session:`) URLs are not supported by the url package in
		// the go-toolkit, so they are used as the raw cache key without parsing
		cacheKey = filename
	} else {
		if bapok {
			// Cannot have non-session publication when bonding auth is enabled
			return nil, problems.BadRequest.Build().
				Detail("non-session publication URLs are not allowed when bonding auth is enabled").Problem()
		}
		loc, err := url.URLFromString(filename)
		if err != nil {
			return nil, problems.BadRequest.Build().Wrap(err).
				Detail("failed creating URL from filepath").Problem()
		}
		u = url.BaseFile.Resolve(loc).(url.AbsoluteURL) // Turn relative filepaths into file:/// URLs
		cacheKey = u.String()
	}

	dat, ok := s.lfu.Get(cacheKey)
	if !ok {
		var doc *session.ReadingSessionDocument
		if isSession {
			if s.config.ReadingSessionFetcher == nil {
				return nil, problems.NotImplemented.Build().
					Detail("reading session API is not available").Problem()
			}
			target, err := readingSessionDataURL(filename)
			if err != nil {
				return nil, problems.BadRequest.Build().Wrap(err).
					Detail("invalid reading session URL").Problem()
			}

			doc, err = s.config.ReadingSessionFetcher.Fetch(ctx, target)
			if err != nil {
				return nil, problems.BadGateway.Build().Wrap(err).
					Detail("failed fetching reading session data").Problem()
			}

			if _, err := doc.Enforce(); err != nil {
				return nil, problems.From(err)
			}

			pubURL, hasPub := doc.PublicationURL()
			if !hasPub {
				return nil, problems.BadGateway.Build().
					Detail("reading session document is missing a publication URL").Problem()
			}
			loc, err := url.URLFromString(pubURL)
			if err != nil {
				return nil, problems.Internal("failed creating URL from publication URL", err)
			}
			u = url.BaseFile.Resolve(loc).(url.AbsoluteURL)
		}

		var pub *pub.Publication
		var remote bool
		var err error
		audioOpts := []audio.Option{
			audio.WithConcurrency(int(s.config.AudioParsingConcurrency)),
			audio.WithCacheBlockSize(int(s.config.AudioParsingCacheBlockSize)),
		}
		if !s.config.AudioEmbeddedChapters {
			audioOpts = append(audioOpts, audio.WithoutEmbeddedChapters())
		}
		if s.config.AudioParsingCacheRetain && !u.IsFile() {
			// Keep the blocks fetched while probing remote audiobooks attached
			// to the cached publication: browsers request the container header
			// and every chapter sample before starting playback, and those
			// ranges are then served from memory instead of new remote
			// requests. Local files don't need it — serving them is cheap.
			audioOpts = append(audioOpts, audio.WithRetainedCache())
		}
		config := streamer.Config{
			InferA11yMetadata:    s.config.InferA11yMetadata,
			HttpClient:           s.remote.HTTP,
			AddServiceLinks:      true,
			IgnoreDefaultParsers: true,
			Parsers: []parser.PublicationParser{
				epub.NewParser(nil),
				pdf.NewParser(),
				webpub.NewParser(s.remote.HTTP),
				image.NewParser(),
				audio.NewRichParser(audioOpts...),
			},
		}
		if doc != nil {
			config.OnCreatePublication = doc.Injector()
		}
		if !s.remote.AcceptsScheme(u.Scheme()) {
			return nil, problems.BadRequest.Build().
				Detailf("unacceptable scheme %q", u.Scheme().String()).Problem()
		}
		if u.IsFile() {
			// Confine the request to LocalDirectory at the syscall layer.
			// os.Root refuses any traversal outside the directory — via "..",
			// an absolute path, or a symlink — using the OS's own path
			// semantics. That closes both the Windows separator-mismatch gap
			// (slash-only path.Clean misses backslash "..") and the
			// symlink-escape gap a purely lexical containment check leaves
			// open. go-toolkit's fetcher still opens the file by path, so this
			// Stat is the confinement gate; the path handed to the streamer is
			// the same one it validates.
			root, err := os.OpenRoot(s.remote.LocalDirectory)
			if err != nil {
				return nil, problems.Internal("failed opening file directory", err)
			}
			// os.Root paths are relative to the root, so drop the leading
			// slash the URL path carries; an empty path is the directory
			// itself.
			rel := strings.TrimPrefix(path.Clean(u.Path()), "/")
			if rel == "" {
				rel = "."
			}
			_, statErr := root.Stat(rel)
			root.Close()
			if statErr != nil {
				// The path either escapes the root or does not exist; either
				// way the client only learns the publication was not found.
				// The offending path stays on the wrapped error, for logs.
				return nil, problems.NotFound.Build().
					Wrap(fmt.Errorf("failed resolving %s within %s: %w", rel, s.remote.LocalDirectory, statErr)).
					Detail("Publication not found").Problem()
			}

			fpath, err := url.FromFilepath(filepath.Join(s.remote.LocalDirectory, rel))
			if err != nil {
				return nil, problems.Internal("failed creating URL from filepath", err)
			}

			pub, err = streamer.New(config).Open(ctx, asset.File(fpath), "")
			if err != nil {
				// The local path stays on the wrapped error for logs; the
				// client-facing detail must not disclose the server's
				// filesystem layout or act as a file-existence oracle.
				return nil, problems.NotFound.Build().
					Wrap(fmt.Errorf("failed opening %s: %w", fpath.String(), err)).
					Detail("Publication not found").Problem()
			}
		} else {
			switch u.Scheme() {
			case url.SchemeS3:
				remote = true
				if s.remote.S3 == nil {
					return nil, problems.NotImplemented.Build().
						Detail("S3 client not configured").Problem()
				}
				config.ArchiveFactory = archive.NewS3ArchiveFactory(s.remote.S3, archive.NewDefaultRemoteArchiveConfig())
				pub, err = streamer.New(config).Open(ctx, asset.S3(s.remote.S3, u), "")
				if err != nil {
					// Never serialize u into the detail: in session mode it is
					// the resolved publication URL, which may carry upstream
					// credentials (e.g. a presigned query string).
					return nil, problems.BadGateway.Build().
						Wrap(fmt.Errorf("failed opening %s: %w", u.String(), err)).
						Detail("upstream fetch failed").Problem()
				}
			case url.SchemeGS:
				remote = true
				if s.remote.GCS == nil {
					return nil, problems.NotImplemented.Build().
						Detail("GCS client not configured").Problem()
				}
				config.ArchiveFactory = archive.NewGCSArchiveFactory(s.remote.GCS, archive.NewDefaultRemoteArchiveConfig())
				pub, err = streamer.New(config).Open(ctx, asset.GCS(s.remote.GCS, u), "")
				if err != nil {
					return nil, problems.BadGateway.Build().
						Wrap(fmt.Errorf("failed opening %s: %w", u.String(), err)).
						Detail("upstream fetch failed").Problem()
				}
			case url.SchemeHTTP, url.SchemeHTTPS:
				remote = true
				if s.remote.HTTP == nil {
					return nil, problems.NotImplemented.Build().
						Detail("HTTP client not configured").Problem()
				}
				config.ArchiveFactory = archive.NewHTTPArchiveFactory(s.remote.HTTP, archive.NewDefaultRemoteArchiveConfig())
				pub, err = streamer.New(config).Open(ctx, asset.HTTP(s.remote.HTTP, u), "")
				if err != nil {
					return nil, problems.BadGateway.Build().
						Wrap(fmt.Errorf("failed opening %s: %w", u.String(), err)).
						Detail("upstream fetch failed").Problem()
				}
			default:
				return nil, problems.BadRequest.Build().
					Detailf("unsupported scheme %q", u.Scheme().String()).Problem()
			}
		}

		// Cache the publication. Retain before inserting so eviction can never
		// close it before this request has a hold on it; the caller balances
		// this with a deferred Release.
		encPub := cache.EncapsulatePublication(pub, doc, remote)
		encPub.Retain()
		s.lfu.Set(cacheKey, encPub)

		// Record the bond for the opening device before returning, so a
		// `devices: N` session cannot admit N+1 devices via subsequent cached
		// requests that find an empty bond list.
		if err := s.enforceBonding(ctx, doc); err != nil {
			encPub.Release()
			return nil, err
		}

		return encPub, nil
	}
	cp := dat.(*cache.CachedPublication)

	cp.Mu.RLock()
	sessionDoc := cp.Session
	cp.Mu.RUnlock()

	if sessionDoc != nil && sessionDoc.Rights != nil {
		if err := s.enforceBonding(ctx, sessionDoc); err != nil {
			return nil, err
		}

		refresh, err := sessionDoc.Rights.Enforce()
		if refresh {
			if s.config.ReadingSessionFetcher == nil {
				return nil, problems.NotImplemented.Build().
					Detail("reading session API is not available").Problem()
			}
			target, err := readingSessionDataURL(filename)
			if err != nil {
				return nil, problems.Internal("invalid reading session URL", err)
			}

			var doc *session.ReadingSessionDocument
			doc, err = s.config.ReadingSessionFetcher.Fetch(ctx, target)
			if err != nil {
				return nil, problems.BadGateway.Build().Wrap(err).
					Detail("failed fetching reading session data").Problem()
			}

			if _, err := doc.Enforce(); err != nil {
				return nil, problems.From(err)
			}

			cp.RefreshSession(doc)
		} else if err != nil {
			return nil, problems.From(err)
		}
	}

	// Retain for the returning caller. A failure means the entry was evicted
	// and closed between the cache lookup and here (rare). The closed entry is
	// already gone from the cache map (TinyLFU deletes before OnEvict), so
	// re-opening is enough — a blind Del here could instead evict a fresher
	// entry a concurrent miss had repopulated under the same key.
	if !cp.Retain() {
		return s.getPublication(ctx)
	}
	return cp, nil
}

func (s *Server) enforceBonding(ctx context.Context, doc *session.ReadingSessionDocument) error {
	if doc == nil || doc.Rights == nil {
		return nil
	}
	bap, ok := s.config.Auth.(auth.BondingAuthProvider)
	if !ok {
		return nil
	}
	bd, ok := ctx.Value(auth.BondingRecordContextKey).(auth.BondingData)
	if !ok {
		return problems.Internal("missing bonding data in context for bonding auth provider", nil)
	}
	deviceCount := doc.Rights.DeviceCount(bap.MaxDevices())
	if deviceCount == 0 {
		return nil
	}
	// Ceiling for unreasonable per-subject device counts.
	limit := deviceCount
	if bap.MaxBondsPerSubject() > 0 && bap.MaxBondsPerSubject() < limit {
		limit = bap.MaxBondsPerSubject()
	}

	now := time.Now()
	// Perform the whole read-check-append-write atomically under the cache's
	// per-key lock: otherwise concurrent requests from distinct devices each
	// read the same bond snapshot, each pass the limit check, and each write
	// back — a lost-update race that admits more than `limit` devices and
	// data-races on the shared backing array. The authoritative bond list is
	// the one passed in here (not the request-time snapshot), and it is cloned
	// before any mutation so the cache's backing array is never written.
	var limitErr error
	bap.Cache().Compute(bd.Key, func(oldBonds []auth.AgentBond, _ bool) ([]auth.AgentBond, otter.ComputeOp) {
		bonds := slices.Clone(oldBonds)
		foundIdx := -1
		for i := range bonds {
			if bonds[i].Device == bd.Device {
				foundIdx = i
				break
			}
		}
		if foundIdx >= 0 {
			bonds[foundIdx].Hash = bd.Hash
			bonds[foundIdx].UpdatedAt = now
			return bonds, otter.WriteOp
		}
		if uint16(len(bonds)) >= limit {
			var newestBond time.Time
			for _, b := range bonds {
				if b.UpdatedAt.After(newestBond) {
					newestBond = b.UpdatedAt
				}
			}
			if time.Since(newestBond) < bap.MinDeviceEvictionInterval() {
				limitErr = problems.DeviceLimitExceeded.Build().
					Detail("device limit exceeded for this publication").Problem()
				return oldBonds, otter.CancelOp
			}
			bonds = auth.EvictBonds(bonds, limit-1)
		}
		return append(bonds, auth.AgentBond{
			Device:    bd.Device,
			Hash:      bd.Hash,
			UpdatedAt: now,
		}), otter.WriteOp
	})
	return limitErr
}

func (s *Server) getManifest(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	// Load the publication
	cp, err := s.getPublication(req.Context())
	if err != nil {
		slog.Error("failed opening publication", "error", err)
		problems.Write(err, w, req)
		return
	}
	defer cp.Release()

	// Create "self" link in manifest
	scheme := "http://"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		// Note: this is never going to be 100% accurate behind proxies,
		// but it's better than nothing for a dev server.
		scheme = "https://"
	}
	rPath, _ := s.router.Get("manifest").URLPath("path", vars["path"])

	selfUrl, err := url.AbsoluteURLFromString(scheme + req.Host + rPath.String())
	if err != nil {
		slog.Error("failed creating self URL", "error", err)
		problems.Write(problems.Internal("failed creating self URL", err), w, req)
		return
	}

	// Hold the read lock while reading manifest fields and marshalling, so a
	// concurrent RefreshSession cannot mutate the manifest mid-read.
	cp.Mu.RLock()
	conformsTo := conformsToAsMimetype(cp.Publication.Manifest.Metadata.ConformsTo)
	selfLink := &manifest.Link{
		Rels:      manifest.Strings{"self"},
		MediaType: &conformsTo,
		Href:      manifest.NewHREF(selfUrl),
	}
	var j []byte
	if s.config.JSONIndent == "" {
		j, err = json.Marshal(cp.Publication.Manifest.ToMap(selfLink))
	} else {
		j, err = json.MarshalIndent(cp.Publication.Manifest.ToMap(selfLink), "", s.config.JSONIndent)
	}
	cachedAt := cp.CachedAt
	cp.Mu.RUnlock()

	if err != nil {
		slog.Error("failed marshalling manifest JSON", "error", err)
		problems.Write(problems.Internal("failed marshalling manifest JSON", err), w, req)
		return
	}

	// Add headers
	w.Header().Set("content-type", conformsTo.String()+"; charset=utf-8")
	w.Header().Set("cache-control", "private, must-revalidate")

	// Etag based on hash of the manifest bytes
	etag := `"` + strconv.FormatUint(xxh3.Hash(j), 36) + `"`
	w.Header().Set("Etag", etag)

	http.ServeContent(w, req, "manifest.json", cachedAt, bytes.NewReader(j))
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	// Load the publication
	cp, err := s.getPublication(r.Context())
	if err != nil {
		slog.Error("failed opening publication", "error", err)
		problems.Write(err, w, r)
		return
	}
	defer cp.Release()

	// Parse asset path from mux vars
	href, err := url.URLFromDecodedPath(path.Clean(vars["asset"]))
	if err != nil {
		slog.Error("failed parsing asset path as URL", "error", err)
		problems.Write(problems.BadRequest.Build().Wrap(err).Detail("failed parsing asset path as URL").Problem(), w, r)
		return
	}
	rawHref := href.Raw()
	rawHref.RawQuery = r.URL.Query().Encode() // Add the query parameters of the URL
	href, _ = url.RelativeURLFromGo(rawHref)  // Turn it back into a go-toolkit relative URL

	// Resolve the link and acquire a resource handle under the read lock,
	// so a concurrent RefreshSession cannot mutate the manifest mid-lookup.
	cp.Mu.RLock()
	link := cp.Publication.LinkWithHref(href)
	if link == nil {
		cp.Mu.RUnlock()
		problems.Write(problems.NotFound.Build().Detailf("asset %q not found in publication", href.String()).Problem(), w, r)
		return
	}
	finalLink := *link
	if finalLink.Href.IsTemplated() {
		finalLink.Href = manifest.NewHREF(finalLink.URL(nil, convertURLValuesToMap(r.URL.Query())))
	}
	res := cp.Publication.Get(r.Context(), finalLink)
	cp.Mu.RUnlock()
	remote := cp.Remote
	defer res.Close()

	// Get asset length in bytes
	l, rerr := res.Length(r.Context())
	if rerr != nil {
		slog.Error("failed reading asset length", "error", rerr)
		problems.Write(problems.FromResourceError(rerr), w, r)
		return
	}

	// Patch mimetype where necessary
	contentType := finalLink.MediaType.String()
	if sub, ok := mimeSubstitutions[contentType]; ok {
		contentType = sub
	}
	if slices.Contains(utfCharsetNeeded, contentType) {
		contentType += "; charset=utf-8"
	}
	w.Header().Set("content-type", contentType)
	w.Header().Set("cache-control", "private, max-age=86400, immutable")
	w.Header().Set("content-length", strconv.FormatInt(l, 10))

	// Range reading assets. hasRange tracks whether a Range header was
	// actually parsed: `bytes=0-0` also produces start == 0 && end == 0, so
	// those values cannot be used to detect the absence of a range request.
	var start, end int64
	hasRange := false
	rangeHeader := r.Header.Get("range")
	if rangeHeader != "" {
		rng, err := httprange.ParseRange(rangeHeader, l)
		if err != nil {
			slog.Error("failed parsing range header", "error", err)
			problems.Write(problems.RangeNotSatisfiable.Build().Wrap(err).Detail("failed parsing range header").Problem(), w, r)
			return
		}
		if len(rng) > 1 {
			slog.Error("no support for multiple read ranges")
			problems.Write(problems.NotImplemented.Build().Detail("multiple read ranges are not supported").Problem(), w, r)
			return
		}
		if len(rng) > 0 {
			hasRange = true
			w.Header().Set("content-range", rng[0].ContentRange(l))
			start = rng[0].Start
			end = start + rng[0].Length - 1
			w.Header().Set("content-length", strconv.FormatInt(rng[0].Length, 10))
		}
	}
	if hasRange {
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.Header().Set("accept-ranges", "bytes")
	}

	cres, ok := res.(fetcher.CompressedResource)
	es, esok := res.(fetcher.EfficientStreamer)
	normalResponse := func() {
		if r.Method == http.MethodHead {
			return
		}

		if hasRange && start == 0 && end == 0 {
			// A one-byte range at offset 0 is inexpressible through the
			// toolkit's (start, end) pair, where 0,0 means the whole
			// resource — read the first two bytes and send only the first.
			var bin []byte
			bin, rerr = res.Read(r.Context(), 0, 1)
			if rerr == nil && len(bin) > 0 {
				_, err = w.Write(bin[:1])
				if err != nil {
					rerr = fetcher.Other(err)
				}
			}
			return
		}

		if remote && (!esok || !es.HasEfficientStream()) {
			// The resource cannot stream the range efficiently from a remote
			// source (e.g. a deflate-compressed archive entry, whose ranged
			// Stream decompresses from the entry start on every call), so
			// read the whole range with a single call instead.
			var bin []byte
			bin, rerr = res.Read(r.Context(), start, end)
			if rerr == nil {
				_, err = w.Write(bin)
				if err != nil {
					rerr = fetcher.Other(err)
				}
			}
		} else {
			// Local resources and efficient streamers (bare remote files,
			// stored entries in remote archives) retrieve only the requested
			// range and pipe it through: the first byte reaches the client as
			// soon as it is available, memory use is bounded, and a client
			// abort cancels the remote transfer via the request context.
			_, rerr = res.Stream(r.Context(), w, start, end)
		}
	}
	if ok && cres.CompressedAs(archive.CompressionMethodDeflate) && !hasRange {
		// Stream the asset in compressed format if supported by the user agent
		if supportsEncoding(r, "deflate") {
			headers := func() {
				w.Header().Set("content-encoding", "deflate")
				w.Header().Set("content-length", strconv.FormatInt(cres.CompressedLength(r.Context()), 10))
			}
			if r.Method == http.MethodHead {
				headers()
				return
			}
			if remote {
				var bin []byte
				bin, rerr = cres.ReadCompressed(r.Context())
				if rerr == nil {
					headers()
					_, err = w.Write(bin)
					if err != nil {
						rerr = fetcher.Other(err)
					}
				}
			} else {
				headers()
				_, rerr = cres.StreamCompressed(r.Context(), w)
			}
		} else if supportsEncoding(r, "gzip") && l <= archive.GzipMaxLength {
			headers := func() {
				w.Header().Set("content-encoding", "gzip")
				w.Header().Set("content-length", strconv.FormatInt(cres.CompressedLength(r.Context())+archive.GzipWrapperLength, 10))
			}
			if r.Method == http.MethodHead {
				headers()
				return
			}
			if remote {
				var bin []byte
				bin, rerr = cres.ReadCompressedGzip(r.Context())
				if rerr == nil {
					headers()
					_, err = w.Write(bin)
					if err != nil {
						rerr = fetcher.Other(err)
					}
				}
			} else {
				headers()
				_, rerr = cres.StreamCompressedGzip(r.Context(), w)
			}
		} else {
			normalResponse()
		}
	} else {
		normalResponse()
	}

	if rerr != nil {
		if problems.IsClientDisconnect(r.Context(), rerr.Cause) {
			// Ignore client aborts: the write fails with a broken pipe or a
			// reset HTTP/2 stream, or the canceled request context interrupts
			// the remote read mid-stream.
			return
		}

		slog.Error("failed streaming asset", "error", rerr.Error())
	}

}
