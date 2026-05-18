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

func (cp *CachedPublication) OnEvict() {
	// Cleanup
	if cp.Publication != nil {
		cp.Publication.Close()
	}
}
