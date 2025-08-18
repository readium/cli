package client

import (
	"fmt"
	"net/http"
	"net/url"
)

type authTransport struct {
	Authorization string
	Whitelist     []*url.URL
	Transport     http.RoundTripper
}

func (a *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !validateAgainstWhitelist(req.URL, a.Whitelist) {
		return nil, fmt.Errorf("request to %s is not allowed by the whitelist", req.URL)
	}

	if a.Authorization == "" {
		return a.transport().RoundTrip(req)
	}
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", a.Authorization)
	return a.transport().RoundTrip(req2)
}

func (a *authTransport) transport() http.RoundTripper {
	if a.Transport != nil {
		return a.Transport
	}
	return http.DefaultTransport
}

func newAuthenticatedRoundTripper(auth string, whitelist []*url.URL, transport *http.Transport) http.RoundTripper {
	return &authTransport{
		Authorization: auth,
		Whitelist:     whitelist,
		Transport:     transport,
	}
}
