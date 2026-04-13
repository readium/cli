package cache

import (
	"time"

	"github.com/readium/cli/pkg/serve/content"
	"github.com/readium/go-toolkit/pkg/pub"
)

// CachedPublication implements Evictable
type CachedPublication struct {
	*pub.Publication
	Content  *content.ContentDocument
	Remote   bool
	CachedAt time.Time
}

func EncapsulatePublication(pub *pub.Publication, content *content.ContentDocument, remote bool) *CachedPublication {
	return &CachedPublication{pub, content, remote, time.Now()}
}

func (cp *CachedPublication) OnEvict() {
	// Cleanup
	if cp.Publication != nil {
		cp.Publication.Close()
	}
}
