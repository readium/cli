package inspector

import (
	"testing"

	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, href string) url.URL {
	t.Helper()
	u, err := url.URLFromString(href)
	require.NoError(t, err)
	return u
}

// image is a guided navigation image object, as the HTML converter emits for an
// <img> with the given alt.
func image(t *testing.T, href string, alt string) guidednavigation.GuidedNavigationObject {
	t.Helper()
	obj := guidednavigation.GuidedNavigationObject{
		ImgRef: mustURL(t, href),
		Role:   []guidednavigation.GuidedNavigationRole{guidednavigation.RoleImage},
	}
	if alt != "" {
		obj.Description = guidednavigation.NewTextDescription(alt)
	}
	return obj
}

// within nests objects in an object with the given roles, as the HTML converter
// does for the content of a block.
func within(roles []guidednavigation.GuidedNavigationRole, objs ...guidednavigation.GuidedNavigationObject) guidednavigation.GuidedNavigationObject {
	return guidednavigation.GuidedNavigationObject{Role: roles, Children: objs}
}

func inspectAccessModes(t *testing.T, m manifest.Manifest, svc *stubGuideService, mode streamer.InferA11yMetadata) manifest.Manifest {
	t.Helper()
	run := CreateInspection([]Inspector{&AccessModes{GuidedNavigationService: svc, Mode: mode}})
	result := m.Copy(run)
	require.NoError(t, run.Error())
	return result
}

// mergedAccessModes returns the access modes inferred for a publication whose
// only document holds the given objects, merged into its accessibility metadata.
func mergedAccessModes(t *testing.T, objs ...guidednavigation.GuidedNavigationObject) []manifest.A11yAccessMode {
	t.Helper()
	svc, m := singleDoc(objs...)
	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)
	if result.Metadata.Accessibility == nil {
		return nil
	}
	return result.Metadata.Accessibility.AccessModes
}

var (
	textual           = manifest.A11yAccessModeTextual
	visual            = manifest.A11yAccessModeVisual
	bodyRole          = []guidednavigation.GuidedNavigationRole{guidednavigation.RoleBody}
	presentationRole  = []guidednavigation.GuidedNavigationRole{guidednavigation.RolePresentation}
	coverSectionRoles = []guidednavigation.GuidedNavigationRole{guidednavigation.RoleSection, guidednavigation.RoleCover}
)

func TestAccessModes_Text(t *testing.T) {
	assert.Equal(t, []manifest.A11yAccessMode{textual}, mergedAccessModes(t, within(bodyRole, paragraph)))
}

func TestAccessModes_TextAndImage(t *testing.T) {
	modes := mergedAccessModes(t, within(bodyRole,
		paragraph,
		// Nested, as the HTML converter does for an image inside of a block
		within(nil, image(t, "images/map.jpg", "A map")),
	))
	assert.Equal(t, []manifest.A11yAccessMode{textual, visual}, modes)
}

// The description of an image is not text of the publication: a publication
// made of described images is not textual.
func TestAccessModes_ImageDescriptionIsNotText(t *testing.T) {
	modes := mergedAccessModes(t, within(bodyRole, image(t, "images/page1.jpg", "The first page")))
	assert.Equal(t, []manifest.A11yAccessMode{visual}, modes)
}

func TestAccessModes_BlankTextIsNotText(t *testing.T) {
	blank := guidednavigation.GuidedNavigationObject{
		// What's left of a paragraph holding only an image and a non-breaking space
		Text: guidednavigation.GuidedNavigationText{Plain: "  ", SSML: `<readium:image id="image1"/>`},
	}
	assert.Empty(t, mergedAccessModes(t, within(bodyRole, blank)))
}

// The text of a page break marker is the number of its page.
func TestAccessModes_PageBreakLabelIsNotText(t *testing.T) {
	assert.Empty(t, mergedAccessModes(t, within(bodyRole, pagebreak)))
}

// An image with an empty alt is emitted without a description. That's not
// enough to tell that it's decorative.
func TestAccessModes_ImageWithoutDescriptionIsVisual(t *testing.T) {
	modes := mergedAccessModes(t, within(bodyRole, image(t, "images/figure.jpg", "")))
	assert.Equal(t, []manifest.A11yAccessMode{visual}, modes)
}

func TestAccessModes_DecorativeImageIsNotVisual(t *testing.T) {
	decorative := image(t, "images/ornament.png", "")
	decorative.Role = presentationRole
	// A presentational <video>
	decorativeVideo := guidednavigation.GuidedNavigationObject{
		VideoRef: mustURL(t, "video/background.mp4"),
		Role:     presentationRole,
	}

	modes := mergedAccessModes(t, within(bodyRole, paragraph, decorative, decorativeVideo))
	assert.Equal(t, []manifest.A11yAccessMode{textual}, modes)
}

func TestAccessModes_VideoAndInlineImagesAreVisual(t *testing.T) {
	for name, obj := range map[string]guidednavigation.GuidedNavigationObject{
		"video": {
			VideoRef: mustURL(t, "video/clip.mp4"),
			Role:     []guidednavigation.GuidedNavigationRole{guidednavigation.RoleVideo},
		},
		"video without a source": {
			Role:        []guidednavigation.GuidedNavigationRole{guidednavigation.RoleVideo},
			Description: guidednavigation.NewTextDescription("A clip"),
		},
		// An inline SVG, or an element with role="img"
		"image which is not a resource": {
			Role:        []guidednavigation.GuidedNavigationRole{guidednavigation.RoleImage},
			Description: guidednavigation.NewTextDescription("A blue square"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, []manifest.A11yAccessMode{visual}, mergedAccessModes(t, within(bodyRole, obj)))
		})
	}
}

func TestAccessModes_CoverIsNotVisual(t *testing.T) {
	coverRole := image(t, "images/front.jpg", "Cover")
	coverRole.Role = append(coverRole.Role, guidednavigation.RoleCover)

	for name, obj := range map[string]guidednavigation.GuidedNavigationObject{
		// The resource of the link with the cover relation, wherever it's used
		"cover resource":               image(t, "images/cover.jpg", "Cover"),
		"cover resource with fragment": image(t, "images/cover.jpg#xywh=0,0,100,100", "Cover"),
		"cover role":                   coverRole,
		"cover role on an ancestor":    within(coverSectionRoles, within(nil, image(t, "images/front.jpg", ""))),
	} {
		t.Run(name, func(t *testing.T) {
			svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
				"cover.xhtml": guide(within(bodyRole, obj)),
			}}
			cover := manifest.Link{
				Href:      manifest.MustNewHREFFromString("images/cover.jpg", false),
				MediaType: &mediatype.JPEG,
				Rels:      manifest.Strings{"cover"},
			}
			m := manifest.Manifest{
				ReadingOrder: manifest.LinkList{htmlLink("cover.xhtml")},
				Resources:    manifest.LinkList{cover},
			}

			result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)

			assert.Nil(t, result.Metadata.Accessibility)
		})
	}
}

// The cover role doesn't hide what follows the cover.
func TestAccessModes_ImageAfterCoverIsVisual(t *testing.T) {
	modes := mergedAccessModes(t, within(bodyRole,
		within(coverSectionRoles, image(t, "images/front.jpg", "")),
		image(t, "images/map.jpg", ""),
	))
	assert.Equal(t, []manifest.A11yAccessMode{visual}, modes)
}

// Only the documents of the reading order are read, and not its navigation
// document: the others are not content to be read through.
func TestAccessModes_OnlyReadsReadingOrderContent(t *testing.T) {
	content := guide(within(bodyRole, paragraph, image(t, "images/map.jpg", "A map")))
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		"nav.xhtml":      content,
		"page1.xhtml":    guide(within(bodyRole, image(t, "images/cover.jpg", "Cover"))),
		"footnote.xhtml": content,
	}}
	nav := htmlLink("nav.xhtml")
	nav.Rels = manifest.Strings{"contents"}
	cover := manifest.Link{
		Href:      manifest.MustNewHREFFromString("images/cover.jpg", false),
		MediaType: &mediatype.JPEG,
		Rels:      manifest.Strings{"cover"},
	}
	m := manifest.Manifest{
		ReadingOrder: manifest.LinkList{nav, htmlLink("page1.xhtml")},
		// A document with linear="no", and an image: not a document to read
		Resources: manifest.LinkList{htmlLink("footnote.xhtml"), cover},
	}

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)

	assert.Equal(t, []string{"page1.xhtml"}, svc.calls)
	assert.Nil(t, result.Metadata.Accessibility)
}

func TestAccessModes_StopsWhenBothAreFound(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		"ch1.xhtml": guide(within(bodyRole, paragraph)),
		"ch2.xhtml": guide(within(bodyRole, image(t, "images/map.jpg", ""))),
		"ch3.xhtml": nil, // Would fail if requested
	}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml"), htmlLink("ch3.xhtml")}}

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)

	assert.Equal(t, []string{"ch1.xhtml", "ch2.xhtml"}, svc.calls)
	require.NotNil(t, result.Metadata.Accessibility)
	assert.Equal(t, []manifest.A11yAccessMode{textual, visual}, result.Metadata.Accessibility.AccessModes)
}

// Access modes are inferred even when the publication declares some, and
// merged with them.
func TestAccessModes_MergedAddsToDeclared(t *testing.T) {
	authored := &manifest.A11y{
		Summary:     "Accessible",
		AccessModes: []manifest.A11yAccessMode{textual},
	}
	svc, m := singleDoc(within(bodyRole, paragraph, image(t, "images/map.jpg", "")))
	m.Metadata.Accessibility = authored

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)

	require.NotNil(t, result.Metadata.Accessibility)
	assert.Equal(t, "Accessible", result.Metadata.Accessibility.Summary)
	assert.Equal(t, []manifest.A11yAccessMode{textual, visual}, result.Metadata.Accessibility.AccessModes)
	// The publication's own object is left untouched
	assert.Equal(t, []manifest.A11yAccessMode{textual}, authored.AccessModes)
}

func TestAccessModes_DeclaredSkipsScan(t *testing.T) {
	authored := &manifest.A11y{AccessModes: []manifest.A11yAccessMode{visual, textual}}
	svc, m := singleDoc(within(bodyRole, paragraph))
	m.Metadata.Accessibility = authored

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataMerged)

	assert.Empty(t, svc.calls)
	assert.Same(t, authored, result.Metadata.Accessibility)
}

func TestAccessModes_SplitAddsToInferred(t *testing.T) {
	svc, m := singleDoc(within(bodyRole, paragraph, image(t, "images/map.jpg", "")))
	m.Metadata.OtherMetadata = map[string]any{}
	// What the streamer's own inference and the other inspectors would have stored
	require.NoError(t, m.Metadata.SetOtherMetadata(manifest.InferredAccessibilityMetadataKey, &manifest.A11y{
		AccessModes: []manifest.A11yAccessMode{manifest.A11yAccessModeAuditory},
		Features:    []manifest.A11yFeature{manifest.A11yFeatureTableOfContents},
	}))
	setInferredA11y(&m.Metadata, "language", "fr")

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataSplit)

	assert.Nil(t, result.Metadata.Accessibility)
	inferred := result.Metadata.InferredAccessibility()
	require.NotNil(t, inferred)
	assert.Equal(t, []manifest.A11yAccessMode{manifest.A11yAccessModeAuditory, textual, visual}, inferred.AccessModes)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents}, inferred.Features)
	// Keys which are not accessibility metadata are kept
	raw := result.Metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey].(map[string]any)
	assert.Equal(t, "fr", raw["language"])
}

func TestAccessModes_SplitWithoutExistingInferred(t *testing.T) {
	svc, m := singleDoc(within(bodyRole, paragraph))

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataSplit)

	assert.Nil(t, result.Metadata.Accessibility)
	raw, ok := result.Metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"accessMode": []any{"textual"}}, raw)
}

// The inferred access modes come in addition to the publication's own: the
// ones it declares are not repeated.
func TestAccessModes_SplitDoesNotRepeatDeclared(t *testing.T) {
	authored := &manifest.A11y{AccessModes: []manifest.A11yAccessMode{textual}}
	svc, m := singleDoc(within(bodyRole, paragraph, image(t, "images/map.jpg", "")))
	m.Metadata.Accessibility = authored

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataSplit)

	assert.Equal(t, []manifest.A11yAccessMode{textual}, result.Metadata.Accessibility.AccessModes)
	inferred := result.Metadata.InferredAccessibility()
	require.NotNil(t, inferred)
	assert.Equal(t, []manifest.A11yAccessMode{visual}, inferred.AccessModes)
}

func TestAccessModes_NothingFound(t *testing.T) {
	svc, m := singleDoc(within(bodyRole))

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataSplit)

	assert.Nil(t, result.Metadata.Accessibility)
	assert.NotContains(t, result.Metadata.OtherMetadata, manifest.InferredAccessibilityMetadataKey)
}

func TestAccessModes_DisabledMode(t *testing.T) {
	svc, m := singleDoc(within(bodyRole, paragraph))

	result := inspectAccessModes(t, m, svc, streamer.InferA11yMetadataNo)

	assert.Empty(t, svc.calls)
	assert.Nil(t, result.Metadata.Accessibility)
	assert.Empty(t, result.Metadata.OtherMetadata)
}

func TestAccessModes_PropagatesConversionError(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": nil}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}}

	run := CreateInspection([]Inspector{&AccessModes{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataMerged}})
	m.Copy(run)

	require.Error(t, run.Error())
	assert.Contains(t, run.Error().Error(), "ch1.xhtml")
	assert.Contains(t, run.Error().Error(), "access modes")
}
