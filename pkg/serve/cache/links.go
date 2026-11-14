package cache

import (
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/util/url"
)

const (
	publicationLinkCacheSize = 128
	maxCachedLinkHrefLength  = 4096
)

type publicationLinkCache struct {
	links map[string]manifest.Link
	keys  [publicationLinkCacheSize]string
	next  int
}

// LinkWithHrefLocked memoizes successful lookups until RefreshSession. The
// caller must hold Mu.RLock or Mu.Lock, including while using the returned link.
// It returns a shallow copy, matching Publication.LinkWithHref; mutations to
// shared maps and slices in links still require external synchronization.
func (cp *CachedPublication) LinkWithHrefLocked(href url.URL) *manifest.Link {
	key := href.String()
	// Bound retained URL bytes as well as entry count. Long URLs still use the
	// complete toolkit lookup, including its template and query behavior.
	if len(key) > maxCachedLinkHrefLength {
		return cp.Publication.LinkWithHref(href)
	}

	cp.linkMu.Lock()
	if cp.linkCache != nil {
		if link, found := cp.linkCache.links[key]; found {
			cp.linkMu.Unlock()
			return &link
		}
	}
	cp.linkMu.Unlock()

	// Keep misses out of the cache and allow unrelated lookups to proceed
	// concurrently. The caller's publication lock excludes session refreshes.
	link := cp.Publication.LinkWithHref(href)
	if link == nil {
		return nil
	}

	cp.linkMu.Lock()
	defer cp.linkMu.Unlock()
	if cp.linkCache == nil {
		cp.linkCache = &publicationLinkCache{links: make(map[string]manifest.Link)}
	}
	cached := cp.linkCache
	if _, found := cached.links[key]; !found {
		if len(cached.links) == publicationLinkCacheSize {
			delete(cached.links, cached.keys[cached.next])
		}
		cached.links[key] = *link
		cached.keys[cached.next] = key
		cached.next = (cached.next + 1) % publicationLinkCacheSize
	}
	return link
}
