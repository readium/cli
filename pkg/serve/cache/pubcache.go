package cache

import (
	"sync"
	"time"

	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/pub"
)

// CachedPublication implements Evictable
type CachedPublication struct {
	*pub.Publication
	Session  *session.ReadingSessionDocument
	Remote   bool
	CachedAt time.Time

	rightsService session.RightsService
	Mu            sync.RWMutex

	// refcounting so the underlying publication (and its archive/file
	// handles) is never closed while a request is still streaming from it.
	// The cache signals eviction via OnEvict; the actual Close happens only
	// once the entry has been evicted AND the last in-flight reader has
	// released it. refMu guards all three fields.
	refMu   sync.Mutex
	refs    int
	evicted bool
	closed  bool
}

func EncapsulatePublication(p *pub.Publication, doc *session.ReadingSessionDocument, remote bool) *CachedPublication {
	cp := &CachedPublication{
		Publication: p,
		Session:     doc,
		Remote:      remote,
		CachedAt:    time.Now(),
	}
	if doc != nil {
		cp.rightsService = doc.RightsService()
	}
	return cp
}

// RefreshSession swaps in a freshly-fetched reading session document and
// re-applies its metadata/links/rights onto the existing publication in place,
// avoiding an expensive reopen. The publication's injected rights service is
// updated atomically; the manifest mutation is guarded by Mu.
func (cp *CachedPublication) RefreshSession(doc *session.ReadingSessionDocument) {
	cp.Mu.Lock()
	defer cp.Mu.Unlock()
	cp.Session = doc
	cp.CachedAt = time.Now()
	if doc == nil {
		return
	}
	if cp.rightsService != nil && doc.Rights != nil {
		cp.rightsService.Update(doc.Rights)
	}
	doc.Merge(&cp.Publication.Manifest)
}

// Retain marks the publication as in-use by one more reader. It returns false
// if the publication has already been closed, in which case the caller must
// not use it and should re-open. Every successful Retain must be paired with a
// Release.
func (cp *CachedPublication) Retain() bool {
	cp.refMu.Lock()
	defer cp.refMu.Unlock()
	if cp.closed {
		return false
	}
	cp.refs++
	return true
}

// Release drops one reader's hold on the publication, closing it if the cache
// has already evicted the entry and this was the last reader.
func (cp *CachedPublication) Release() {
	cp.refMu.Lock()
	doClose := false
	if cp.refs > 0 {
		cp.refs--
	}
	if cp.refs == 0 && cp.evicted && !cp.closed {
		cp.closed = true
		doClose = true
	}
	cp.refMu.Unlock()
	if doClose {
		cp.close()
	}
}

func (cp *CachedPublication) OnEvict() {
	cp.refMu.Lock()
	doClose := false
	cp.evicted = true
	if cp.refs == 0 && !cp.closed {
		cp.closed = true
		doClose = true
	}
	cp.refMu.Unlock()
	if doClose {
		cp.close()
	}
}

func (cp *CachedPublication) close() {
	if cp.Publication != nil {
		cp.Publication.Close()
	}
}
