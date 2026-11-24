package inspector

import (
	"encoding/json"
	"testing"

	"github.com/readium/go-toolkit/pkg/guidednavigation"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// text is a guided navigation text object in the given language.
func text(lang string) guidednavigation.GuidedNavigationObject {
	return guidednavigation.GuidedNavigationObject{
		Text: guidednavigation.GuidedNavigationText{Plain: "Some text", Language: lang},
	}
}

// ssmlText is a guided navigation text object in the given language, with SSML markup.
func ssmlText(lang string, ssml string) guidednavigation.GuidedNavigationObject {
	return guidednavigation.GuidedNavigationObject{
		Text: guidednavigation.GuidedNavigationText{Plain: "Some text", SSML: ssml, Language: lang},
	}
}

func inspectLanguages(t *testing.T, m manifest.Manifest, inspectors ...Inspector) manifest.Manifest {
	t.Helper()
	run := CreateInspection(inspectors)
	result := m.Copy(run)
	require.NoError(t, run.Error())
	return result
}

// inferredLanguage returns the raw "language" value of the inferred accessibility object.
func inferredLanguage(t *testing.T, m manifest.Manifest) any {
	t.Helper()
	inferred, ok := m.Metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey].(map[string]any)
	if !ok {
		return nil
	}
	return inferred["language"]
}

func singleDoc(objs ...guidednavigation.GuidedNavigationObject) (*stubGuideService, manifest.Manifest) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(objs...)}}
	return svc, manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}}
}

func TestLanguages_OrderedByStringCount(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		// German comes first, but is the least used
		"ch1.xhtml": guide(text("de"), text("fr"), text("en")),
		"ch2.xhtml": guide(
			text("en"),
			// Nested, as the HTML converter does for blocks
			guidednavigation.GuidedNavigationObject{Children: []guidednavigation.GuidedNavigationObject{
				text("fr"),
				{Children: []guidednavigation.GuidedNavigationObject{text("en")}},
			}},
		),
	}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml")}}

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []any{"en", "fr", "de"}, inferredLanguage(t, result))
	assert.Nil(t, result.Metadata.Accessibility)
	assert.Empty(t, result.Metadata.Languages, "the publication's own languages are left alone")
}

func TestLanguages_TiesKeepOrderOfAppearance(t *testing.T) {
	svc, m := singleDoc(text("ja"), text("en"), text("fr"), text("en"), text("ja"), text("fr"))

	// Maps are involved: make sure the order doesn't depend on their iteration
	for range 20 {
		svc.calls = nil
		result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})
		assert.Equal(t, []any{"ja", "en", "fr"}, inferredLanguage(t, result))
	}
}

func TestLanguages_SingleLanguageIsAString(t *testing.T) {
	svc, m := singleDoc(text("en"), text("en"))

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, "en", inferredLanguage(t, result))

	out, err := json.Marshal(result.Metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey])
	require.NoError(t, err)
	assert.JSONEq(t, `{"language": "en"}`, string(out))
}

func TestLanguages_NormalizesTags(t *testing.T) {
	svc, m := singleDoc(
		text("EN-us"), text("en_US"), text(" en-US "), // The same language
		text("en"), text("en"), // Not the same as en-US: regions are kept
		text("zh-hant-tw"),
		text("iw"), // Deprecated code for Hebrew
	)

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []any{"en-US", "en", "zh-Hant-TW", "he"}, inferredLanguage(t, result))
}

func TestLanguages_IgnoresUndeclaredAndInvalid(t *testing.T) {
	svc, m := singleDoc(
		text(""),             // No language in effect
		text("not a tag"),    // Not well-formed
		text("und"),          // Undetermined
		text("english"),      // Too long to be a language subtag
		text("jp"),           // Well-formed, but there is no such language (Japanese is "ja")
		text("zz-ZZ"),        // Same, with a region that does exist
		paragraph, pagebreak, // No language either
	)

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []string{"ch1.xhtml"}, svc.calls)
	assert.Nil(t, result.Metadata.OtherMetadata, "nothing is written when no language is found")
}

func TestLanguages_UnknownSubtagIsDropped(t *testing.T) {
	// Well-formed, but there is no such region or script
	svc, m := singleDoc(text("en-QK"), text("en-Abcd"), text("en-GB"))

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []any{"en", "en-GB"}, inferredLanguage(t, result))
}

func TestLanguages_CountsInlineRuns(t *testing.T) {
	svc, m := singleDoc(
		// Markup as generated by the HTML converter
		ssmlText("en", `This job requires a certain <lang xml:lang="fr">savoir faire</lang> that can only be acquired over time.`),
		ssmlText("en", `A <emphasis xml:lang="fr">déjà vu</emphasis>, a <lang xml:lang="fr">je ne sais quoi</lang> &amp; some <lang xml:lang="de">Zeitgeist</lang>.<break/><readium:image id="img1"/>`),
		text("de"),
		text("de"),
	)

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	// fr: 3 inline runs, en: 2 texts, de: 2 texts and 1 inline run
	assert.Equal(t, []any{"fr", "de", "en"}, inferredLanguage(t, result))
}

func TestLanguages_TextWhollyInOtherLanguages(t *testing.T) {
	svc, m := singleDoc(
		// Nothing in this text is in English, despite its base language
		ssmlText("en", `<lang xml:lang="fr">Bonjour</lang> <lang xml:lang="de">Guten Tag</lang><break/>`),
		// Emphasis in the base language still makes it English
		ssmlText("en", `<emphasis>Hello</emphasis> <lang xml:lang="fr">Bonjour</lang>`),
		text("ja"), text("ja"), text("ja"),
	)

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	// ja: 3, fr: 2, then de and en with 1 each, in order of appearance
	assert.Equal(t, []any{"ja", "fr", "de", "en"}, inferredLanguage(t, result))
}

func TestLanguages_BrokenSSMLStillCountsText(t *testing.T) {
	// No text in English was seen before the markup breaks, but it can't be ruled out
	svc, m := singleDoc(ssmlText("en", `<lang xml:lang="fr">Bonjour</lang> <emphasis attr=>`))

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	// A text's own language is counted before its inline runs
	assert.Equal(t, []any{"en", "fr"}, inferredLanguage(t, result))
}

func TestLanguages_KeepsExistingInferred(t *testing.T) {
	svc, m := singleDoc(text("en"), text("fr"), text("en"))
	m.Metadata.OtherMetadata = map[string]any{"other": "value"}
	// What the streamer's own inference would have stored
	require.NoError(t, m.Metadata.SetOtherMetadata(manifest.InferredAccessibilityMetadataKey, &manifest.A11y{
		AccessModes: []manifest.A11yAccessMode{manifest.A11yAccessModeVisual},
		Features:    []manifest.A11yFeature{manifest.A11yFeatureTableOfContents},
	}))

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []any{"en", "fr"}, inferredLanguage(t, result))
	assert.Equal(t, "value", result.Metadata.OtherMetadata["other"])
	inferred := result.Metadata.InferredAccessibility()
	require.NotNil(t, inferred)
	assert.Equal(t, []manifest.A11yAccessMode{manifest.A11yAccessModeVisual}, inferred.AccessModes)
	assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents}, inferred.Features)
}

// The inferred accessibility object is shared between inspectors: neither of
// them may drop what the other one wrote, whichever runs first.
func TestLanguages_WithPageBreakMarkers(t *testing.T) {
	newInspectors := func(svc *stubGuideService) (Inspector, Inspector) {
		return &Languages{GuidedNavigationService: svc},
			&PageBreakMarkers{GuidedNavigationService: svc, Mode: streamer.InferA11yMetadataSplit}
	}

	for name, order := range map[string]func(languages, pageBreaks Inspector) []Inspector{
		"languages first":   func(l, p Inspector) []Inspector { return []Inspector{l, p} },
		"page breaks first": func(l, p Inspector) []Inspector { return []Inspector{p, l} },
	} {
		t.Run(name, func(t *testing.T) {
			svc, m := singleDoc(text("en"), pagebreak, text("fr"), text("en"))
			m.Metadata.OtherMetadata = map[string]any{}
			require.NoError(t, m.Metadata.SetOtherMetadata(manifest.InferredAccessibilityMetadataKey, &manifest.A11y{
				Features: []manifest.A11yFeature{manifest.A11yFeatureTableOfContents},
			}))

			result := inspectLanguages(t, m, order(newInspectors(svc))...)

			assert.Equal(t, []any{"en", "fr"}, inferredLanguage(t, result))
			inferred := result.Metadata.InferredAccessibility()
			require.NotNil(t, inferred)
			assert.Equal(t, []manifest.A11yFeature{manifest.A11yFeatureTableOfContents, manifest.A11yFeaturePageBreakMarkers}, inferred.Features)
		})
	}
}

func TestLanguages_ScansEachDocumentOnce(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": guide(text("en"), text("fr"), text("fr"))}}
	doc := htmlLink("ch1.xhtml")
	img := manifest.Link{Href: manifest.MustNewHREFFromString("cover.png", false), MediaType: &mediatype.PNG}
	m := manifest.Manifest{
		ReadingOrder:    manifest.LinkList{doc, img},
		Resources:       manifest.LinkList{doc},
		TableOfContents: manifest.LinkList{doc},
	}

	result := inspectLanguages(t, m, &Languages{GuidedNavigationService: svc})

	assert.Equal(t, []string{"ch1.xhtml"}, svc.calls)
	// Counted three times, English would come first
	assert.Equal(t, []any{"fr", "en"}, inferredLanguage(t, result))
}

func TestLanguages_PropagatesConversionError(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": nil}}
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml")}}

	run := CreateInspection([]Inspector{&Languages{GuidedNavigationService: svc}})
	m.Copy(run)

	require.Error(t, run.Error())
	assert.Contains(t, run.Error().Error(), "languages")
	assert.Contains(t, run.Error().Error(), "failed converting ch1.xhtml")
}

func TestCacheGuides_GeneratesEachGuideOnce(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{
		"ch1.xhtml": guide(text("en")),
		"ch2.xhtml": guide(text("fr"), text("fr")),
	}}
	cached := CacheGuides(svc)
	m := manifest.Manifest{ReadingOrder: manifest.LinkList{htmlLink("ch1.xhtml"), htmlLink("ch2.xhtml")}}

	result := inspectLanguages(t, m,
		&ImageUsage{GuidedNavigationService: cached},
		&PageBreakMarkers{GuidedNavigationService: cached, Mode: streamer.InferA11yMetadataSplit},
		&Languages{GuidedNavigationService: cached},
	)

	assert.Equal(t, []string{"ch1.xhtml", "ch2.xhtml"}, svc.calls)
	assert.Equal(t, []any{"fr", "en"}, inferredLanguage(t, result))
	assert.False(t, cached.HasGuideForResource("missing.xhtml"))
}

func TestCacheGuides_DoesNotCacheErrors(t *testing.T) {
	svc := &stubGuideService{docs: map[string]*guidednavigation.GuidedNavigationDocument{"ch1.xhtml": nil}}
	cached := CacheGuides(svc)

	_, err := cached.GuideForResource(t.Context(), "ch1.xhtml")
	require.Error(t, err)
	_, err = cached.GuideForResource(t.Context(), "ch1.xhtml")
	require.Error(t, err)

	assert.Equal(t, []string{"ch1.xhtml", "ch1.xhtml"}, svc.calls)
}
