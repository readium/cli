package session

import (
	"context"
	"fmt"
	"net/http"

	"encoding/json"
)

const SchemeReadingSession = "session"

type Fetcher interface {
	Fetch(ctx context.Context, url string) (*ReadingSessionDocument, error)
}

type HTTPFetcher struct {
	client *http.Client
}

func (f *HTTPFetcher) Fetch(ctx context.Context, url string) (*ReadingSessionDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading session API returned status %d", resp.StatusCode)
	}

	var doc ReadingSessionDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed parsing reading session API response: %w", err)
	}

	if _, ok := doc.PublicationURL(); !ok {
		return nil, fmt.Errorf("reading session document has no publication link")
	}

	return &doc, nil
}

func NewHTTPFetcher(client *http.Client) Fetcher {
	return &HTTPFetcher{
		client: client,
	}
}
