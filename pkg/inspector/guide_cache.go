package inspector

import (
	"context"

	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/pub"
)

// CacheGuides wraps a guided navigation service so that the guide of each
// resource is generated only once, however many inspectors read it.
//
// Every guide stays in memory for as long as the returned service does, and the
// same document is handed to each caller, which must not modify it. The
// returned service is not safe for concurrent use.
func CacheGuides(service pub.GuidedNavigationService) pub.GuidedNavigationService {
	return &cachedGuides{
		GuidedNavigationService: service,
		docs:                    make(map[string]*guidednavigation.GuidedNavigationDocument),
	}
}

type cachedGuides struct {
	pub.GuidedNavigationService
	docs map[string]*guidednavigation.GuidedNavigationDocument
}

// GuideForResource implements pub.GuidedNavigationService
func (c *cachedGuides) GuideForResource(ctx context.Context, href string) (*guidednavigation.GuidedNavigationDocument, error) {
	if doc, ok := c.docs[href]; ok {
		return doc, nil
	}
	doc, err := c.GuidedNavigationService.GuideForResource(ctx, href)
	if err != nil {
		return nil, err
	}
	c.docs[href] = doc
	return doc, nil
}
