package cache

import (
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
}

func EncapsulatePublication(pub *pub.Publication, session *session.ReadingSessionDocument, remote bool) *CachedPublication {
	return &CachedPublication{pub, session, remote, time.Now()}
}

func (cp *CachedPublication) OnEvict() {
	// Cleanup
	if cp.Publication != nil {
		cp.Publication.Close()
	}
}
