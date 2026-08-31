package inspector

import (
	"io/fs"

	"github.com/readium/go-toolkit/pkg/analyzer"
	"github.com/readium/go-toolkit/pkg/manifest"
)

type Image struct {
	Filesystem fs.FS
	Algorithms []manifest.HashAlgorithm
}

// Name implements Inspector
func (n *Image) Name() string {
	return "image"
}

// InspectHREF implements Inspector
func (n *Image) InspectHREF(href manifest.HREF) (*manifest.HREF, error) {
	// Identity
	return nil, nil
}

// InspectLink implements Inspector
func (n *Image) InspectLink(link manifest.Link) (*manifest.Link, error) {
	if link.MediaType == nil || !link.MediaType.IsBitmap() {
		return nil, nil
	}

	return analyzer.InspectImage(n.Filesystem, link, n.Algorithms)
}

// InspectManifest implements Inspector
func (n *Image) InspectManifest(manifest manifest.Manifest) (*manifest.Manifest, error) {
	// Identity
	return nil, nil
}

// InspectMetadata implements Inspector
func (n *Image) InspectMetadata(metadata manifest.Metadata) (*manifest.Metadata, error) {
	// Identity
	return nil, nil
}
