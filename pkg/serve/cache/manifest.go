package cache

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/zeebo/xxh3"
)

// ManifestResponse contains an immutable serialized manifest. Callers must not
// modify JSON; concurrent requests may be serving the same bytes.
type ManifestResponse struct {
	JSON        []byte
	ETag        string
	ContentType string
	Modified    time.Time
}

type manifestJSON struct {
	self   string
	indent string
	ManifestResponse
}

// ManifestResponse reuses serialization and its ETag until the session changes.
// Only one representation is retained per publication: varying hosts, tokens or
// indentation cannot grow an unbounded response cache.
func (cp *CachedPublication) ManifestResponse(self url.URL, indent string) (ManifestResponse, error) {
	cp.Mu.RLock()
	defer cp.Mu.RUnlock()
	cp.manifestMu.Lock()
	defer cp.manifestMu.Unlock()

	selfString := self.String()
	if cached := cp.manifestJSON; cached != nil && cached.self == selfString && cached.indent == indent {
		return cached.ManifestResponse, nil
	}

	mime := mediatype.ReadiumWebpubManifest
	for _, profile := range cp.Publication.Manifest.Metadata.ConformsTo {
		switch profile {
		case manifest.ProfileDivina:
			mime = mediatype.ReadiumDivinaManifest
		case manifest.ProfileAudiobook:
			mime = mediatype.ReadiumAudiobookManifest
		default:
			continue
		}
		break
	}
	selfLink := &manifest.Link{
		Rels:      manifest.Strings{"self"},
		MediaType: &mime,
		Href:      manifest.NewHREF(self),
	}
	var data []byte
	var err error
	if indent == "" {
		data, err = json.Marshal(cp.Publication.Manifest.ToMap(selfLink))
	} else {
		data, err = json.MarshalIndent(cp.Publication.Manifest.ToMap(selfLink), "", indent)
	}
	if err != nil {
		return ManifestResponse{}, err
	}
	response := ManifestResponse{
		JSON:        data,
		ETag:        `"` + strconv.FormatUint(xxh3.Hash(data), 36) + `"`,
		ContentType: mime.String(),
		Modified:    cp.CachedAt,
	}
	cp.manifestJSON = &manifestJSON{self: selfString, indent: indent, ManifestResponse: response}
	return response, nil
}
