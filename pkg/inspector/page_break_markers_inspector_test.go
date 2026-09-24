package inspector

import (
	"context"
	"errors"
	"testing"

	"github.com/readium/go-toolkit/pkg/fetcher"
	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubGuideService serves canned guided navigation documents and records
// which ones were requested. A nil document fails the conversion.
type stubGuideService struct {
	docs  map[string]*guidednavigation.GuidedNavigationDocument
	calls []string
}

func (s *stubGuideService) Links() manifest.LinkList { return nil }
func (s *stubGuideService) Get(ctx context.Context, link manifest.Link) (fetcher.Resource, bool) {
	return nil, false
}
func (s *stubGuideService) Close() {}
func (s *stubGuideService) HasGuideForResource(href string) bool {
	_, ok := s.docs[href]
	return ok
}
func (s *stubGuideService) GuideForResource(ctx context.Context, href string) (*guidednavigation.GuidedNavigationDocument, error) {
	s.calls = append(s.calls, href)
	doc, ok := s.docs[href]
	if !ok {
		return nil, errors.New("no guide for " + href)
	}
	if doc == nil {
		return nil, errors.New("failed converting " + href)
	}
	return doc, nil
}

func guide(objs ...guidednavigation.GuidedNavigationObject) *guidednavigation.GuidedNavigationDocument {
	return &guidednavigation.GuidedNavigationDocument{Guided: objs}
}

var (
	paragraph = guidednavigation.GuidedNavigationObject{
		Text: guidednavigation.GuidedNavigationText{Plain: "Some text"},
	}
	pagebreak = guidednavigation.GuidedNavigationObject{
		Role: []guidednavigation.GuidedNavigationRole{guidednavigation.RolePagebreak},
		Text: guidednavigation.GuidedNavigationText{Plain: "12"},
	}
	// A page break buried two levels deep, as the HTML converter nests them in blocks
	nestedPagebreak = guidednavigation.GuidedNavigationObject{
		Children: []guidednavigation.GuidedNavigationObject{
			paragraph,
			{Children: []guidednavigation.GuidedNavigationObject{pagebreak}},
		},
	}
)

func htmlLink(href string) manifest.Link {
	return manifest.Link{Href: manifest.MustNewHREFFromString(href, false), MediaType: &mediatype.XHTML}
}

func inspectPageBreaks(t *testing.T, m manifest.Manifest, n *PageBreakMarkers) manifest.Manifest {
	t.Helper()
	run := CreateInspection([]Inspector{n})
	result := m.Copy(run)
	require.NoError(t, run.Error())
	return result
}

func TestPageBreakMarkers_MergedAddsFeature(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		"ch1.xhtml": guide(paragraph),
		"ch2.xhtml": guide(nestedPagebreak),
	}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml")}}

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged})

	require.NotNil(t, result.Metadata.Accessibility)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeaturePageBreakMarkers}, result.Metadata.Accessibility.Features)
	assert.Nil(t, result.Metadata.InferredAccessibility())
	assert.Equal(t, []string{"ch1.xhtml", "ch2.xhtml"}, svc.calls)
}

func TestPageBreakMarkers_StopsAtFirstMarker(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		"ch1.xhtml": guide(pagebreak),
		"ch2.xhtml": guide(paragraph),
		"ch3.xhtml": nil, // Would fail if requested
	}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml"), htmlLink("ch3.xhtml")}}

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged})

	assert.Equal(t, []string{"ch1.xhtml"}, svc.calls)
	require.NotNil(t, result.Metadata.Accessibility)
	assert.Contains(t, result.Metadata.Accessibility.Features, manifest.A11yFeaturePageBreakMarkers)
}

func TestPageBreakMarkers_MergedKeepsAuthoredMetadata(t *testing.T) {
	authored := &manifest.A11y{
		Summary:  "Accessible",
		Features: []manifest.A11yFeature{manifest.A11yFeatureTableOfContents},
	}
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(pagebreak)}}
	m := manifest.Manifest{
		Metadata:     manifest.Metadata{Accessibility: authored},
		ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")},
	}

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged})

	require.NotNil(t, result.Metadata.Accessibility)
	assert.Equal(t, "Accessible", result.Metadata.Accessibility.Summary)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents, manifest.A11yFeaturePageBreakMarkers}, result.Metadata.Accessibility.Features)
	// The publication's own object is left untouched
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents}, authored.Features)
}

func TestPageBreakMarkers_SplitAddsToInferred(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(pagebreak)}}
	m := manifest.Manifest{
		Metadata:     manifest.Metadata{OtherMetadata: map[string]interface{}{}},
		ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")},
	}
	// What the streamer's own inference would have stored
	require.NoError(t, m.Metadata.SetOtherMetadata(manifest.InferredAccessibilityMetadataKey, &manifest.A11y{
		AccessModes: []manifest.A11yAccessMode{manifest.A11yAccessModeVisual},
		Features:    []manifest.A11yFeature{manifest.A11yFeatureTableOfContents},
	}))

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataSplit})

	assert.Nil(t, result.Metadata.Accessibility)
	inferred := result.Metadata.InferredAccessibility()
	require.NotNil(t, inferred)
	assert.Equal(t, []manifest.A11yAccessMode{manifest.A11yAccessModeVisual}, inferred.AccessModes)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents, manifest.A11yFeaturePageBreakMarkers}, inferred.Features)
}

func TestPageBreakMarkers_SplitWithoutExistingInferred(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(pagebreak)}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}} // No OtherMetadata at all

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataSplit})

	assert.Nil(t, result.Metadata.Accessibility)
	inferred := result.Metadata.InferredAccessibility()
	require.NotNil(t, inferred)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeaturePageBreakMarkers}, inferred.Features)
}

func TestPageBreakMarkers_NoMarkers(t *testing.T) {
	for _, mode := range []streamer.InferA11yMetadata{streamer.InferA11yMetadataMerged, streamer.InferA11yMetadataSplit} {
		svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
			"ch1.xhtml": guide(paragraph),
			"ch2.xhtml": guide(guidednavigation.GuidedNavigationObject{Children: []guidednavigation.GuidedNavigationObject{paragraph}}),
		}}
		m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml")}}

		result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: mode})

		assert.Equal(t, []string{"ch1.xhtml", "ch2.xhtml"}, svc.calls)
		assert.Nil(t, result.Metadata.Accessibility)
		assert.Nil(t, result.Metadata.InferredAccessibility())
	}
}

func TestPageBreakMarkers_AlreadyDeclaredSkipsScan(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(pagebreak)}}
	m := manifest.Manifest{
		Metadata: manifest.Metadata{Accessibility: &manifest.A11y{
			Features: []manifest.A11yFeature{manifest.A11yFeaturePageBreakMarkers},
		}},
		ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")},
	}

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged})

	assert.Empty(t, svc.calls)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeaturePageBreakMarkers}, result.Metadata.Accessibility.Features)
}

func TestPageBreakMarkers_ScansEachDocumentOnce(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(paragraph)}}
	doc := htmlLink("ch1.xhtml")
	img := manifest.Link{Href: manifest.MustNewHREFFromString("cover.png", false), MediaType: &mediatype.PNG}
	m := manifest.Manifest{
		ReadingOrder:    manifest.LinkList{doc, img},
		Resources:       manifest.LinkList{doc},
		TableOfContents: manifest.LinkList{doc},
	}

	inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged})

	assert.Equal(t, []string{"ch1.xhtml"}, svc.calls)
}

func TestPageBreakMarkers_DisabledMode(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(pagebreak)}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}}

	result := inspectPageBreaks(t, m, &PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataNo})

	assert.Empty(t, svc.calls)
	assert.Nil(t, result.Metadata.Accessibility)
	assert.Nil(t, result.Metadata.InferredAccessibility())
}

func TestPageBreakMarkers_PropagatesConversionError(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": nil}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}}

	run := CreateInspection([]Inspector{&PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged}})
	m.Copy(run)

	require.Error(t, run.Error())
	assert.Contains(t, run.Error().Error(), "page break markers")
	assert.Contains(t, run.Error().Error(), "failed converting ch1.xhtml")
}
