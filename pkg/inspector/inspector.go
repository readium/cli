package inspector

import (
	"github.com/pkg/errors"
	"github.com/readium/go-toolkit/pkg/manifest"
)

type Inspector interface {
	Name() string
	InspectHREF(href manifest.HREF) (*manifest.HREF, error)
	InspectLink(link manifest.Link) (*manifest.Link, error)
	InspectManifest(manifest manifest.Manifest) (*manifest.Manifest, error)
	InspectMetadata(metadata manifest.Metadata) (*manifest.Metadata, error)
}

type Run struct {
	inspectors []Inspector
	err        error
}

func CreateInspection(inspectors []Inspector) *Run {
	return &Run{
		inspectors: inspectors,
	}
}

func (n *Run) Error() error {
	return n.err
}

// TransformHREF implements ManifestTransformer
func (n *Run) TransformHREF(href manifest.HREF) manifest.HREF {
	if n.err != nil {
		return href
	}
	for i := range n.inspectors {
		newHREF, err := n.inspectors[i].InspectHREF(href)
		if err != nil {
			n.err = errors.Wrap(err, "failed inspecting href "+href.String()+" with inspector for "+n.inspectors[i].Name())
			return href
		}
		if newHREF != nil {
			href = *newHREF
		}
	}
	return href
}

// TransformLink implements ManifestTransformer
func (n *Run) TransformLink(link manifest.Link) manifest.Link {
	if n.err != nil {
		return link
	}
	for i := range n.inspectors {
		newLink, err := n.inspectors[i].InspectLink(link)
		if err != nil {
			n.err = errors.Wrap(err, "failed inspecting link "+link.Href.String()+" with inspector "+n.inspectors[i].Name())
			return link
		}
		if newLink != nil {
			link = *newLink
		}
	}
	return link
}

// TransformManifest implements ManifestTransformer
func (n *Run) TransformManifest(manifest manifest.Manifest) manifest.Manifest {
	if n.err != nil {
		return manifest
	}
	for i := range n.inspectors {
		newManifest, err := n.inspectors[i].InspectManifest(manifest)
		if err != nil {
			n.err = errors.Wrap(err, "failed inspecting manifest with inspector "+n.inspectors[i].Name())
			return manifest
		}
		if newManifest != nil {
			manifest = *newManifest
		}
	}
	return manifest
}

// TransformMetadata implements ManifestTransformer
func (n *Run) TransformMetadata(metadata manifest.Metadata) manifest.Metadata {
	if n.err != nil {
		return metadata
	}
	for i := range n.inspectors {
		newMetadata, err := n.inspectors[i].InspectMetadata(metadata)
		if err != nil {
			n.err = errors.Wrap(err, "failed inspecting metadata with inspector "+n.inspectors[i].Name())
			return metadata
		}
		if newMetadata != nil {
			metadata = *newMetadata
		}
	}
	return metadata
}
