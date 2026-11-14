package cache

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/xxh3"
)

func TestManifestResponseMatchesSerialization(t *testing.T) {
	for _, profile := range []manifest.Profile{manifest.ProfileEPUB, manifest.ProfileDivina, manifest.ProfileAudiobook} {
		for _, indent := range []string{"", "  "} {
			t.Run(fmt.Sprintf("%s/%q", profile, indent), func(t *testing.T) {
				cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{
					Metadata: manifest.Metadata{LocalizedTitle: manifest.NewLocalizedStringFromString("A <book> 日本語"), ConformsTo: manifest.Profiles{profile}},
				}}, nil, false)
				mime := mediatype.ReadiumWebpubManifest
				if profile == manifest.ProfileDivina {
					mime = mediatype.ReadiumDivinaManifest
				}
				if profile == manifest.ProfileAudiobook {
					mime = mediatype.ReadiumAudiobookManifest
				}
				for _, href := range []string{"https://one.example/webpub/token/manifest.json", "http://two.example/webpub/other/manifest.json", "https://one.example/webpub/token/manifest.json"} {
					self := url.MustURLFromString(href)
					link := &manifest.Link{Href: manifest.NewHREF(self), Rels: manifest.Strings{"self"}, MediaType: &mime}
					var want []byte
					var err error
					if indent == "" {
						want, err = json.Marshal(cp.Manifest.ToMap(link))
					} else {
						want, err = json.MarshalIndent(cp.Manifest.ToMap(link), "", indent)
					}
					require.NoError(t, err)
					for range 2 {
						got, err := cp.ManifestResponse(self, indent)
						require.NoError(t, err)
						require.Equal(t, want, got.JSON)
						require.Equal(t, `"`+strconv.FormatUint(xxh3.Hash(want), 36)+`"`, got.ETag)
						require.Equal(t, mime.String(), got.ContentType)
						require.Equal(t, cp.CachedAt, got.Modified)
					}
				}
			})
		}
	}
}

func TestManifestResponseSessionRefresh(t *testing.T) {
	cp := EncapsulatePublication(&pub.Publication{Manifest: manifest.Manifest{Metadata: manifest.Metadata{LocalizedTitle: manifest.NewLocalizedStringFromString("Before")}}}, nil, false)
	cp.CachedAt = time.Unix(1700000000, 0)
	self := url.MustURLFromString("https://example.org/webpub/token/manifest.json")
	before, err := cp.ManifestResponse(self, "")
	require.NoError(t, err)
	original := append([]byte(nil), before.JSON...)
	title := manifest.NewLocalizedStringFromString("After")
	cp.RefreshSession(&session.ReadingSessionDocument{Metadata: &session.ReadingSessionMetadata{Title: &title, ConformsTo: manifest.Profiles{manifest.ProfileAudiobook}}})
	after, err := cp.ManifestResponse(self, "")
	require.NoError(t, err)
	require.NotEqual(t, before.ETag, after.ETag)
	require.Contains(t, string(after.JSON), "After")
	require.Equal(t, mediatype.ReadiumAudiobookManifest.String(), after.ContentType)
	require.True(t, after.Modified.After(before.Modified))
	require.Equal(t, original, before.JSON, "refresh must not overwrite bytes already being served")
	pretty, err := cp.ManifestResponse(self, "  ")
	require.NoError(t, err)
	require.NotEqual(t, after.ETag, pretty.ETag)
	require.Contains(t, string(pretty.JSON), "\n  ")
}

func TestManifestResponseConcurrentRefresh(t *testing.T) {
	cp := EncapsulatePublication(&pub.Publication{}, nil, false)
	self := url.MustURLFromString("https://example.org/webpub/token/manifest.json")
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 40 {
				if worker == 0 {
					title := manifest.NewLocalizedStringFromString(fmt.Sprint(i))
					cp.RefreshSession(&session.ReadingSessionDocument{Metadata: &session.ReadingSessionMetadata{Title: &title}})
				} else {
					got, err := cp.ManifestResponse(self, "")
					if err != nil || !json.Valid(got.JSON) {
						t.Errorf("invalid response: %v", err)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}
