package content

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/readium/go-toolkit/pkg/fetcher"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/util/url"
)

type ContentStatus string

const (
	ContentStatusReady     ContentStatus = "ready"
	ContentStatusActive    ContentStatus = "active"
	ContentStatusRevoked   ContentStatus = "revoked"
	ContentStatusReturned  ContentStatus = "returned"
	ContentStatusCancelled ContentStatus = "cancelled"
	ContentStatusExpired   ContentStatus = "expired"
)

type ContentRights struct {
	Status   ContentStatus `json:"status,omitempty"`
	Expires  *time.Time    `json:"expires,omitempty"`
	Copy     *bool         `json:"copy,omitempty"`
	Print    *bool         `json:"print,omitempty"`
	Devtools *bool         `json:"devtools,omitempty"`
	Devices  *int          `json:"devices,omitempty"`
}

// Empty returns true if all fields in the rights object are zero values.
func (r *ContentRights) Empty() bool {
	return r.Status == "" && r.Expires == nil && r.Copy == nil && r.Print == nil && r.Devtools == nil && r.Devices == nil
}

// ContentMetadata contains optional metadata fields that can override
// those in a publication manifest. All fields are pointers or slices
// so that absent fields are distinguishable from zero values.
type ContentMetadata struct {
	Identifier         string                          `json:"identifier,omitempty"`
	Title              *manifest.LocalizedString       `json:"title,omitempty"`
	Subtitle           *manifest.LocalizedString       `json:"subtitle,omitempty"`
	SortAs             *manifest.LocalizedString       `json:"sortAs,omitempty"`
	Type               string                          `json:"@type,omitempty"`
	ConformsTo         manifest.Profiles               `json:"conformsTo,omitempty"`
	Accessibility      *manifest.A11y                  `json:"accessibility,omitempty"`
	Modified           *time.Time                      `json:"modified,omitempty"`
	Published          *time.Time                      `json:"published,omitempty"`
	Languages          manifest.Strings                `json:"language,omitempty"`
	Subjects           []manifest.Subject              `json:"subject,omitempty"`
	Authors            manifest.Contributors           `json:"author,omitempty"`
	Translators        manifest.Contributors           `json:"translator,omitempty"`
	Editors            manifest.Contributors           `json:"editor,omitempty"`
	Artists            manifest.Contributors           `json:"artist,omitempty"`
	Illustrators       manifest.Contributors           `json:"illustrator,omitempty"`
	Letterers          manifest.Contributors           `json:"letterer,omitempty"`
	Pencilers          manifest.Contributors           `json:"penciler,omitempty"`
	Colorists          manifest.Contributors           `json:"colorist,omitempty"`
	Inkers             manifest.Contributors           `json:"inker,omitempty"`
	Narrators          manifest.Contributors           `json:"narrator,omitempty"`
	Contributors       manifest.Contributors           `json:"contributor,omitempty"`
	Publishers         manifest.Contributors           `json:"publisher,omitempty"`
	Imprints           manifest.Contributors           `json:"imprint,omitempty"`
	ReadingProgression manifest.ReadingProgression     `json:"readingProgression,omitempty"`
	Description        string                          `json:"description,omitempty"`
	Duration           *float64                        `json:"duration,omitempty"`
	NumberOfPages      *uint                           `json:"numberOfPages,omitempty"`
	BelongsTo          map[string]manifest.Collections `json:"belongsTo,omitempty"`
}

type ContentDocument struct {
	Links    manifest.LinkList `json:"links"`
	Rights   *ContentRights    `json:"rights,omitempty"`
	Metadata *ContentMetadata  `json:"metadata,omitempty"`
}

// Merge overwrites fields in the manifest with any metadata provided
// by the ContentDocument, and appends non-publication links to the manifest.
func (d *ContentDocument) Merge(m *manifest.Manifest) {
	if d.Metadata != nil {
		meta := d.Metadata
		if meta.Identifier != "" {
			m.Metadata.Identifier = meta.Identifier
		}
		if meta.Title != nil {
			m.Metadata.LocalizedTitle = *meta.Title
		}
		if meta.Subtitle != nil {
			m.Metadata.LocalizedSubtitle = meta.Subtitle
		}
		if meta.SortAs != nil {
			m.Metadata.LocalizedSortAs = meta.SortAs
		}
		if meta.Type != "" {
			m.Metadata.Type = meta.Type
		}
		if len(meta.ConformsTo) > 0 {
			m.Metadata.ConformsTo = meta.ConformsTo
		}
		if meta.Accessibility != nil {
			m.Metadata.Accessibility = meta.Accessibility
		}
		if meta.Modified != nil {
			m.Metadata.Modified = meta.Modified
		}
		if meta.Published != nil {
			m.Metadata.Published = meta.Published
		}
		if len(meta.Languages) > 0 {
			m.Metadata.Languages = meta.Languages
		}
		if len(meta.Subjects) > 0 {
			m.Metadata.Subjects = meta.Subjects
		}
		if len(meta.Authors) > 0 {
			m.Metadata.Authors = meta.Authors
		}
		if len(meta.Translators) > 0 {
			m.Metadata.Translators = meta.Translators
		}
		if len(meta.Editors) > 0 {
			m.Metadata.Editors = meta.Editors
		}
		if len(meta.Artists) > 0 {
			m.Metadata.Artists = meta.Artists
		}
		if len(meta.Illustrators) > 0 {
			m.Metadata.Illustrators = meta.Illustrators
		}
		if len(meta.Letterers) > 0 {
			m.Metadata.Letterers = meta.Letterers
		}
		if len(meta.Pencilers) > 0 {
			m.Metadata.Pencilers = meta.Pencilers
		}
		if len(meta.Colorists) > 0 {
			m.Metadata.Colorists = meta.Colorists
		}
		if len(meta.Inkers) > 0 {
			m.Metadata.Inkers = meta.Inkers
		}
		if len(meta.Narrators) > 0 {
			m.Metadata.Narrators = meta.Narrators
		}
		if len(meta.Contributors) > 0 {
			m.Metadata.Contributors = meta.Contributors
		}
		if len(meta.Publishers) > 0 {
			m.Metadata.Publishers = meta.Publishers
		}
		if len(meta.Imprints) > 0 {
			m.Metadata.Imprints = meta.Imprints
		}
		if meta.ReadingProgression != "" {
			m.Metadata.ReadingProgression = meta.ReadingProgression
		}
		if meta.Description != "" {
			m.Metadata.Description = meta.Description
		}
		if meta.Duration != nil {
			m.Metadata.Duration = meta.Duration
		}
		if meta.NumberOfPages != nil {
			m.Metadata.NumberOfPages = meta.NumberOfPages
		}
		if len(meta.BelongsTo) > 0 {
			m.Metadata.BelongsTo = meta.BelongsTo
		}
	}

	// Merge non-publication links into the manifest, replacing existing links with matching rels
	for _, link := range d.Links {
		if slices.Contains([]string(link.Rels), "publication") {
			continue
		}
		replaced := false
		for i, existing := range m.Links {
			for _, rel := range link.Rels {
				if slices.Contains([]string(existing.Rels), rel) {
					m.Links[i] = link
					replaced = true
					break
				}
			}
			if replaced {
				break
			}
		}
		if !replaced {
			m.Links = append(m.Links, link)
		}
	}
}

// PublicationURL returns the href of the first link with rel "publication".
func (d *ContentDocument) PublicationURL() (string, bool) {
	for _, link := range d.Links {
		if slices.Contains([]string(link.Rels), "publication") {
			return link.Href.String(), true
		}
	}
	return "", false
}

const ContentDocumentService_Name pub.ServiceName = "ContentDocumentService"

// Injector merges the content document metadata/links into the publication, and adds the rights as a service
func (d *ContentDocument) Injector() func(builder *pub.Builder) error {
	return func(builder *pub.Builder) error {
		d.Merge(&builder.Manifest)

		if d.Rights == nil || d.Rights.Empty() {
			return nil
		}

		href, _ := url.URLFromDecodedPath("~content/rights.json")
		link := manifest.Link{
			Href:      manifest.NewHREF(href),
			MediaType: &mediatype.JSON,
			Rels:      manifest.Strings{"rights"},
		}

		svc := &contentRightsService{
			link: link,
			doc:  d.Rights,
		}
		factory := pub.ServiceFactory(func(_ pub.Context, _ bool) pub.Service {
			return svc
		})
		builder.ServicesBuilder.Set(ContentDocumentService_Name, &factory)
		return nil
	}
}

type contentRightsService struct {
	link manifest.Link
	doc  *ContentRights
}

func (s *contentRightsService) Links() manifest.LinkList {
	return manifest.LinkList{s.link}
}

func (s *contentRightsService) Get(_ context.Context, link manifest.Link) (fetcher.Resource, bool) {
	if link.Href.String() != s.link.Href.String() {
		return nil, false
	}
	return fetcher.NewBytesResource(s.link, func() []byte {
		data, _ := json.Marshal(s.doc)
		return data
	}), true
}

func (s *contentRightsService) Close() {}
