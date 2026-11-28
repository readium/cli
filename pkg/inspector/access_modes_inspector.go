package inspector

import (
	"context"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/streamer"
)

// AccessModes infers the textual and visual access modes of a publication from
// the content of its (X)HTML documents, through their guided navigation
// representation:
//   - textual, when a document contains text. Descriptions of images, such as
//     their alt, are not text, and neither is the label of a page break marker.
//   - visual, when a document contains an image or a video which is neither
//     decorative nor a cover. An image is decorative when it carries the
//     [guidednavigation.RolePresentation] role, which the HTML converter assigns
//     to role="presentation" and role="none". An empty alt doesn't make it so.
//     An image is a cover when it is the resource of a link with the cover
//     relation, or when it or one of its ancestors carries the
//     [guidednavigation.RoleCover] role (epub:type="cover" or role="doc-cover").
//
// The guided navigation service has to be set up with
// [github.com/readium/go-toolkit/pkg/guidednavigation/converter.WithDecorativeImages]:
// the converter otherwise leaves out the images with an empty alt, which would
// then count as decorative.
//
// Only the documents of the reading order are read, without its navigation
// document if it has one: a navigation document always contains text, whatever
// the publication is made of. Documents out of the reading order are either not
// part of the content, or not meant to be read as part of it (linear="no").
//
// Access modes are inferred whether or not the publication declares some of its
// own, and only the ones which are missing are added. Mode selects where,
// mirroring the streamer's own accessibility inference: merged into the
// metadata's accessibility object, or into the separate inferred accessibility
// object stored in OtherMetadata. With [streamer.InferA11yMetadataNo], the
// inspector does nothing.
type AccessModes struct {
	GuidedNavigationService pub.GuidedNavigationService
	Mode                    streamer.InferA11yMetadata
}

// Name implements Inspector
func (n *AccessModes) Name() string {
	return "access modes"
}

// InspectHREF implements Inspector
func (n *AccessModes) InspectHREF(href manifest.HREF) (*manifest.HREF, error) {
	// Identity
	return nil, nil
}

// InspectLink implements Inspector
func (n *AccessModes) InspectLink(link manifest.Link) (*manifest.Link, error) {
	// Links are transformed without telling which collection they belong to,
	// and only the reading order matters here: it is read from the manifest
	return nil, nil
}

// InspectMetadata implements Inspector
func (n *AccessModes) InspectMetadata(metadata manifest.Metadata) (*manifest.Metadata, error) {
	// Identity
	return nil, nil
}

// InspectManifest implements Inspector
func (n *AccessModes) InspectManifest(m manifest.Manifest) (*manifest.Manifest, error) {
	if n.Mode != streamer.InferA11yMetadataMerged && n.Mode != streamer.InferA11yMetadataSplit {
		return nil, nil
	}

	// The access modes there already are, which don't need to be looked for.
	// When split, the publication's own are not repeated in the inferred ones.
	var known []manifest.A11yAccessMode
	if m.Metadata.Accessibility != nil {
		known = slices.Clone(m.Metadata.Accessibility.AccessModes)
	}
	var inferred *manifest.A11y
	if n.Mode == streamer.InferA11yMetadataSplit {
		if inferred = m.Metadata.InferredAccessibility(); inferred != nil {
			known = append(known, inferred.AccessModes...)
		}
	}
	needTextual := !slices.Contains(known, manifest.A11yAccessModeTextual)
	needVisual := !slices.Contains(known, manifest.A11yAccessModeVisual)
	if !needTextual && !needVisual {
		return nil, nil
	}

	scan := accessModeScan{
		covers:  make(map[string]struct{}),
		textual: !needTextual,
		visual:  !needVisual,
	}
	for _, link := range m.LinksWithRel("cover") {
		scan.covers[link.Href.String()] = struct{}{}
	}

	for _, link := range m.ReadingOrder {
		if scan.done() {
			break
		}
		if link.MediaType == nil || !link.MediaType.IsHTML() || slices.Contains(link.Rels, "contents") {
			continue
		}
		href := link.Href.String()
		if !n.GuidedNavigationService.HasGuideForResource(href) {
			continue
		}
		doc, err := n.GuidedNavigationService.GuideForResource(context.TODO(), href)
		if err != nil {
			return nil, errors.Wrap(err, "failed loading guide for resource "+href)
		}
		scan.walk(doc.Guided, false)
	}

	var found []manifest.A11yAccessMode
	if needTextual && scan.textual {
		found = append(found, manifest.A11yAccessModeTextual)
	}
	if needVisual && scan.visual {
		found = append(found, manifest.A11yAccessModeVisual)
	}
	if len(found) == 0 {
		return nil, nil
	}

	if n.Mode == streamer.InferA11yMetadataMerged {
		// Work on a copy so the publication's own accessibility object is left untouched
		var a11y manifest.A11y
		if m.Metadata.Accessibility != nil {
			a11y = *m.Metadata.Accessibility
		}
		a11y.AccessModes = append(slices.Clone(a11y.AccessModes), found...)
		m.Metadata.Accessibility = &a11y
	} else {
		modes := found
		if inferred != nil {
			modes = append(slices.Clone(inferred.AccessModes), found...)
		}
		// Only the access modes changed, and only they are written back: the
		// inferred object can hold keys that A11y doesn't model
		setInferredA11y(&m.Metadata, "accessMode", jsonStrings(modes))
	}

	return &m, nil
}

// accessModeScan looks for text and visual content in guided navigation objects.
type accessModeScan struct {
	covers  map[string]struct{} // HREFs of the publication's cover images
	textual bool                // Text was found, or doesn't need to be
	visual  bool                // Visual content was found, or doesn't need to be
}

// done reports whether there is nothing left to look for.
func (s *accessModeScan) done() bool {
	return s.textual && s.visual
}

// walk reads the given objects and their descendants, until there is nothing
// left to look for. inCover tells whether they are part of a cover.
func (s *accessModeScan) walk(objs []guidednavigation.GuidedNavigationObject, inCover bool) {
	for i := range objs {
		if s.done() {
			return
		}
		obj := &objs[i]
		cover := inCover || slices.Contains(obj.Role, guidednavigation.RoleCover)

		// The text of a page break marker is the number of the page
		if !s.textual && !slices.Contains(obj.Role, guidednavigation.RolePagebreak) &&
			strings.TrimSpace(obj.Text.Plain) != "" {
			s.textual = true
		}
		if !s.visual && !cover && s.isVisual(obj) {
			s.visual = true
		}

		s.walk(obj.Children, cover)
	}
}

// isVisual reports whether an object is an image or a video which is neither
// decorative, nor the publication's cover image.
func (s *accessModeScan) isVisual(obj *guidednavigation.GuidedNavigationObject) bool {
	if slices.Contains(obj.Role, guidednavigation.RolePresentation) {
		return false
	}
	if obj.ImgRef != nil {
		_, isCover := s.covers[obj.ImgRef.RemoveFragment().String()]
		return !isCover
	}
	// Videos, and images which are not a resource of their own, such as an
	// inline SVG or an element with role="img"
	return obj.VideoRef != nil ||
		slices.Contains(obj.Role, guidednavigation.RoleImage) ||
		slices.Contains(obj.Role, guidednavigation.RoleVideo)
}
