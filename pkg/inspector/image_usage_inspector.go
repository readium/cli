package inspector

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/util/url"
)

type ImageReference struct {
	Href        url.URL                                      `json:"href"`
	Description guidednavigation.GuidedNavigationDescription `json:"description,omitempty"`
	Role        []guidednavigation.GuidedNavigationRole      `json:"role,omitempty"`
}

func (r ImageReference) MarshalJSON() ([]byte, error) {
	// url.URL and the description are serialized through their string forms,
	// like the toolkit does for guided navigation objects
	res := make(map[string]interface{}, 3)
	if r.Href != nil {
		if s := r.Href.String(); s != "" {
			res["href"] = s
		}
	}
	if !r.Description.Empty() {
		res["description"] = r.Description
	}
	if len(r.Role) > 0 {
		res["role"] = r.Role
	}
	return json.Marshal(res)
}

type ImageUsage struct {
	GuidedNavigationService pub.GuidedNavigationService
	references              map[string][]ImageReference
	uniqueDocs              map[string]struct{}
}

// Name implements Inspector
func (n *ImageUsage) Name() string {
	return "image usage"
}

// InspectHREF implements Inspector
func (n *ImageUsage) InspectHREF(href manifest.HREF) (*manifest.HREF, error) {
	// Identity
	return nil, nil
}

// InspectLink implements Inspector
func (n *ImageUsage) InspectLink(link manifest.Link) (*manifest.Link, error) {
	if link.MediaType == nil {
		return nil, nil
	}
	if link.MediaType.IsHTML() {
		href := link.Href.String()
		if n.uniqueDocs == nil {
			n.uniqueDocs = make(map[string]struct{})
		}
		if _, ok := n.uniqueDocs[href]; ok {
			// Already crawled this doc
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

		var crawl func(objs []guidednavigation.GuidedNavigationObject)
		crawl = func(objs []guidednavigation.GuidedNavigationObject) {
			for i := range objs {
				obj := objs[i]
				if obj.ImgRef != nil {
					if n.references == nil {
						n.references = make(map[string][]ImageReference)
					}
					n.references[obj.ImgRef.String()] = append(n.references[obj.ImgRef.String()], ImageReference{
						Href:        obj.TextRef,
						Description: obj.Description,
						Role:        obj.Role,
					})
				}
				crawl(obj.Children)
			}
		}
		crawl(doc.Guided)
	}

	return nil, nil
}

// InspectManifest implements Inspector
func (n *ImageUsage) InspectManifest(m manifest.Manifest) (*manifest.Manifest, error) {
	// TODO: restrictions based on publication type? E.g. skip audiobooks?

	modLink := func(link *manifest.Link) {
		if n.references == nil || link.MediaType == nil || !link.MediaType.IsImage() {
			return
		}
		// Add references to the link
		refs, ok := n.references[link.Href.String()]
		if ok {
			if link.Properties == nil {
				link.Properties = map[string]any{"references": refs}
			} else {
				// Assume no other references at the moment
				link.Properties["references"] = refs
			}
		}
	}
	for i := range m.ReadingOrder {
		modLink(&m.ReadingOrder[i])
	}
	for i := range m.Resources {
		modLink(&m.Resources[i])
	}

	return &m, nil
}

// InspectMetadata implements Inspector
func (n *ImageUsage) InspectMetadata(metadata manifest.Metadata) (*manifest.Metadata, error) {
	// Identity
	return nil, nil
}
