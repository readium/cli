package cache

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/stretchr/testify/require"
)

func lookupTestLink(href, title string) manifest.Link {
	return manifest.Link{Href: manifest.MustNewHREFFromString(href, false), Title: title}
}

func TestCachedLinkWithHrefMatchesToolkit(t *testing.T) {
	parent := lookupTestLink("OPS/parent.xhtml", "parent")
	parent.Alternates = manifest.LinkList{lookupTestLink("OPS/shared.xhtml", "alternate")}
	parent.Children = manifest.LinkList{lookupTestLink("OPS/shared.xhtml", "child"), lookupTestLink("OPS/child.xhtml", "child-only")}
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{
		ReadingOrder: manifest.LinkList{lookupTestLink("OPS/chapter.xhtml", "reading-order"), parent},
		Resources: manifest.LinkList{
			lookupTestLink("OPS/chapter.xhtml", "resource-duplicate"),
			lookupTestLink("OPS/shared.xhtml", "resource-after-alternate"),
			lookupTestLink("OPS/query.xhtml?mode=night", "query-subset"),
			lookupTestLink("OPS/query.xhtml", "query-fallback"),
			lookupTestLink("OPS/multiple.xhtml?a=1&a=2", "query-multiple-values"),
			{Href: manifest.MustNewHREFFromString("OPS/search{?q,lang}", true), Title: "template"},
			lookupTestLink("OPS/chapter%20one.xhtml", "escaped-space"),
			lookupTestLink("OPS/日本語.xhtml", "unicode"),
			lookupTestLink("https://example.org/cover.png", "absolute"),
		},
		Links: manifest.LinkList{lookupTestLink("OPS/chapter.xhtml", "link-duplicate"), lookupTestLink("license.json", "links-only")},
	}}, nil, false)
	for _, href := range []string{
		"OPS/chapter.xhtml", "OPS/chapter.xhtml?request=1#paragraph", "OPS/../OPS/chapter.xhtml",
		"OPS/parent.xhtml", "OPS/shared.xhtml", "OPS/child.xhtml", "license.json",
		"OPS/query.xhtml?mode=night&extra=1", "OPS/query.xhtml?mode=day", "OPS/query.xhtml#heading",
		"OPS/multiple.xhtml?a=2&a=1&extra=1", "OPS/multiple.xhtml?a=1", "OPS/multiple.xhtml?a=3",
		"OPS/search?q=book&lang=en", "OPS/search?lang=en", "OPS/search?q=book", "OPS/search?q=book&lang=en#part",
		"OPS/chapter%20one.xhtml", "OPS/%E6%97%A5%E6%9C%AC%E8%AA%9E.xhtml", "https://example.org/cover.png",
		"missing.xhtml", "OPS/missing.xhtml?request=1",
	} {
		t.Run(href, func(t *testing.T) {
			u := url.MustURLFromString(href)
			cp.Mu.RLock()
			defer cp.Mu.RUnlock()
			want := cp.Publication.LinkWithHref(u)
			for range 3 {
				got := cp.LinkWithHrefLocked(u)
				require.Equal(t, want, got)
			}
		})
	}
}

func TestCachedLinkWithHrefCopiesResults(t *testing.T) {
	link := lookupTestLink("OPS/chapter.xhtml", "original")
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{ReadingOrder: manifest.LinkList{link}}}, nil, false)
	cp.Mu.RLock()
	defer cp.Mu.RUnlock()
	href := url.MustURLFromString("OPS/chapter.xhtml")
	first := cp.LinkWithHrefLocked(href)
	require.NotNil(t, first)
	first.Title = "changed miss result"
	second := cp.LinkWithHrefLocked(href)
	require.Equal(t, "original", second.Title)
	require.NotSame(t, first, second)
	second.Href = manifest.MustNewHREFFromString("other.xhtml", false)
	second.Title = "changed hit result"
	third := cp.LinkWithHrefLocked(href)
	require.Equal(t, link, *third)
	require.NotSame(t, second, third)
	require.Equal(t, link, cp.Manifest.ReadingOrder[0])
}

func TestCachedLinkWithHrefBoundedFIFO(t *testing.T) {
	resources := make(manifest.LinkList, publicationLinkCacheSize+1)
	for i := range resources {
		resources[i] = lookupTestLink(fmt.Sprintf("assets/%d.png", i), "")
	}
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{Resources: resources}}, nil, false)
	cp.Mu.RLock()
	defer cp.Mu.RUnlock()
	for i := range publicationLinkCacheSize {
		require.NotNil(t, cp.LinkWithHrefLocked(resources[i].URL(nil, nil)))
	}
	require.Len(t, cp.linkCache.links, publicationLinkCacheSize)
	// Hits do not change FIFO order.
	require.NotNil(t, cp.LinkWithHrefLocked(resources[0].URL(nil, nil)))
	require.NotNil(t, cp.LinkWithHrefLocked(resources[publicationLinkCacheSize].URL(nil, nil)))
	require.Len(t, cp.linkCache.links, publicationLinkCacheSize)
	require.NotContains(t, cp.linkCache.links, resources[0].Href.String())
	require.Contains(t, cp.linkCache.links, resources[1].Href.String())
	beforeNext := cp.linkCache.next
	for i := range 20 {
		require.Nil(t, cp.LinkWithHrefLocked(url.MustURLFromString(fmt.Sprintf("missing-%d.png", i))))
	}
	require.Equal(t, beforeNext, cp.linkCache.next, "misses must not consume cache entries")
	// Arbitrary long query strings still resolve through the toolkit, but are
	// not retained by the cache. The short resource uses normal query fallback.
	long := url.MustURLFromString("assets/1.png?q=" + strings.Repeat("x", maxCachedLinkHrefLength))
	require.Equal(t, cp.Publication.LinkWithHref(long), cp.LinkWithHrefLocked(long))
	require.Equal(t, beforeNext, cp.linkCache.next)
	require.NotContains(t, cp.linkCache.links, long.String())
}

func TestCachedLinkWithHrefRefresh(t *testing.T) {
	before := lookupTestLink("license.json", "before")
	before.Rels = manifest.Strings{"license"}
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{Links: manifest.LinkList{before}}}, nil, false)
	href := before.URL(nil, nil)
	cp.Mu.RLock()
	require.Equal(t, "before", cp.LinkWithHrefLocked(href).Title)
	cp.Mu.RUnlock()
	after := before
	after.Title = "after"
	cp.RefreshSession(&session.ReadingSessionDocument{Links: manifest.LinkList{after}})
	require.Nil(t, cp.linkCache)
	cp.Mu.RLock()
	require.Equal(t, "after", cp.LinkWithHrefLocked(href).Title)
	cp.Mu.RUnlock()
	// A nil refresh also invalidates retained publication-derived values.
	cp.RefreshSession(nil)
	require.Nil(t, cp.linkCache)
	cp.Mu.RLock()
	require.Equal(t, "after", cp.LinkWithHrefLocked(href).Title)
	cp.Mu.RUnlock()
}

func TestCachedLinkWithHrefConcurrentRefresh(t *testing.T) {
	link := lookupTestLink("license.json", "0")
	link.Rels = manifest.Strings{"license"}
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{Links: manifest.LinkList{link}}}, nil, false)
	href := link.URL(nil, nil)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 40 {
				if worker == 0 {
					updated := link
					updated.Title = fmt.Sprint(i)
					cp.RefreshSession(&session.ReadingSessionDocument{Links: manifest.LinkList{updated}})
				} else {
					cp.Mu.RLock()
					got := cp.LinkWithHrefLocked(href)
					want := cp.Publication.LinkWithHref(href)
					if got == nil || got.Title != want.Title {
						t.Errorf("cached lookup differs from current manifest: got %v, want %v", got, want)
					}
					cp.Mu.RUnlock()
				}
			}
		})
	}
	wg.Wait()
}

var benchmarkCachedLink *manifest.Link

func BenchmarkPublicationLinkLookup(b *testing.B) {
	// A large real EPUB in the profiling corpus has 5,491 manifest items.
	// Use generated links so these focused benchmarks need no local corpus.
	resources := make(manifest.LinkList, 5491)
	for i := range resources {
		resources[i] = lookupTestLink(fmt.Sprintf("EPUB/images/image-%04d.jpg", i), "")
	}
	for _, target := range []struct {
		name string
		href string
	}{
		{"First", resources[0].Href.String()},
		{"Last", resources[len(resources)-1].Href.String()},
		{"QueryFallback", resources[len(resources)-1].Href.String() + "?request=1"},
		{"Missing", "EPUB/images/missing.jpg"},
	} {
		b.Run(target.name, func(b *testing.B) {
			for _, cached := range []bool{false, true} {
				name := "Original"
				if cached {
					name = "Cached"
				}
				b.Run(name, func(b *testing.B) {
					cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{Resources: resources}}, nil, false)
					href := url.MustURLFromString(target.href)
					cp.Mu.RLock()
					cp.LinkWithHrefLocked(href)
					cp.Mu.RUnlock()
					b.ReportAllocs()
					if cached {
						for b.Loop() {
							cp.Mu.RLock()
							benchmarkCachedLink = cp.LinkWithHrefLocked(href)
							cp.Mu.RUnlock()
						}
					} else {
						for b.Loop() {
							cp.Mu.RLock()
							benchmarkCachedLink = cp.Publication.LinkWithHref(href)
							cp.Mu.RUnlock()
						}
					}
				})
			}
		})
	}
}
