package inspector

import (
	"context"
	"slices"

	"github.com/pkg/errors"
	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/streamer"
)

// PageBreakMarkers detects page break markers in a publication's (X)HTML
// documents through their guided navigation representation, and adds the
// pageBreakMarkers accessibility feature to the manifest when it finds one.
//
// A page break marker is any guided navigation object carrying the
// [guidednavigation.RolePagebreak] role, which the HTML converter assigns to
// elements with epub:type="pagebreak" or role="doc-pagebreak". A single marker
// is enough for the feature to apply, so scanning stops at the first one found.
//
// Mode selects where the feature is written, mirroring the streamer's own
// accessibility inference: merged into the metadata's accessibility object, or
// into the separate inferred accessibility object stored in OtherMetadata.
// With [streamer.InferA11yMetadataNo], the inspector does nothing.
type PageBreakMarkers struct {
	GuidedNavigationService pub.GuidedNavigationService
	Mode                    streamer.InferA11yMetadata

	// A marker was found, or the feature is already present: no more scanning
	found      bool
	uniqueDocs map[string]struct{}
}

// Name implements Inspector
func (n *PageBreakMarkers) Name() string {
	return "page break markers"
}

func (n *PageBreakMarkers) enabled() bool {
	return n.Mode == streamer.InferA11yMetadataMerged || n.Mode == streamer.InferA11yMetadataSplit
}

// InspectHREF implements Inspector
func (n *PageBreakMarkers) InspectHREF(href manifest.HREF) (*manifest.HREF, error) {
	// Identity
	return nil, nil
}

// InspectLink implements Inspector
func (n *PageBreakMarkers) InspectLink(link manifest.Link) (*manifest.Link, error) {
	if n.found || !n.enabled() || link.MediaType == nil || !link.MediaType.IsHTML() {
		return nil, nil
	}

	href := link.Href.String()
	if n.uniqueDocs == nil {
		n.uniqueDocs = make(map[string]struct{})
	}
	if _, ok := n.uniqueDocs[href]; ok {
		// Already scanned this doc
		return nil, nil
	}
	n.uniqueDocs[href] = struct{}{}

	if !n.GuidedNavigationService.HasGuideForResource(href) {
		return nil, nil
	}

	doc, err := n.GuidedNavigationService.GuideForResource(context.TODO(), href)
	if err != nil {
		return nil, errors.Wrap(err, "failed loading guide for resource "+href)
	}
	n.found = hasPageBreak(doc.Guided)

	return nil, nil
}

// hasPageBreak reports whether any object in the tree carries the pagebreak role.
func hasPageBreak(objs []guidednavigation.GuidedNavigationObject) bool {
	for i := range objs {
		if slices.Contains(objs[i].Role, guidednavigation.RolePagebreak) || hasPageBreak(objs[i].Children) {
			return true
		}
	}
	return false
}

// InspectManifest implements Inspector
func (n *PageBreakMarkers) InspectManifest(m manifest.Manifest) (*manifest.Manifest, error) {
	if !n.found {
		return nil, nil
	}

	inferred := &manifest.A11y{Features: []manifest.A11yFeature{manifest.A11yFeaturePageBreakMarkers}}

	switch n.Mode {
	case streamer.InferA11yMetadataMerged:
		// Work on a copy so the publication's own accessibility object is left untouched
		var a11y manifest.A11y
		if m.Metadata.Accessibility != nil {
			a11y = *m.Metadata.Accessibility
		}
		a11y.Merge(inferred)
		m.Metadata.Accessibility = &a11y

	case streamer.InferA11yMetadataSplit:
		a11y := m.Metadata.InferredAccessibility()
		if a11y == nil {
			a11y = &manifest.A11y{}
		}
		a11y.Merge(inferred)
		if m.Metadata.OtherMetadata == nil {
			m.Metadata.OtherMetadata = make(map[string]interface{})
		}
		if err := m.Metadata.SetOtherMetadata(manifest.InferredAccessibilityMetadataKey, a11y); err != nil {
			return nil, errors.Wrap(err, "failed storing inferred accessibility metadata")
		}

	default:
		return nil, nil
	}

	return &m, nil
}

// InspectMetadata implements Inspector
func (n *PageBreakMarkers) InspectMetadata(metadata manifest.Metadata) (*manifest.Metadata, error) {
	// The manifest copy transforms metadata before any link, so this runs
	// before documents are scanned. When the feature is already present where
	// it would be written, there is nothing left to detect: skip the scan.
	if !n.enabled() {
		return nil, nil
	}

	var a11y *manifest.A11y
	switch n.Mode {
	case streamer.InferA11yMetadataMerged:
		a11y = metadata.Accessibility
	case streamer.InferA11yMetadataSplit:
		a11y = metadata.InferredAccessibility()
	}
	if a11y != nil && slices.Contains(a11y.Features, manifest.A11yFeaturePageBreakMarkers) {
		n.found = true
	}

	return nil, nil
}
