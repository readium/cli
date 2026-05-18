package client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/readium/cli/internal/version"
	gv "github.com/readium/go-toolkit/pkg/util/version"
)

type authTransport struct {
	Authorization map[string]string
	Whitelist     []*url.URL
	Transport     http.RoundTripper
}

func (a *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !validateAgainstWhitelist(req.URL, a.Whitelist) {
		return nil, fmt.Errorf("request to %s is not allowed by the whitelist", req.URL)
	}
	req2 := req.Clone(req.Context())

	req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; readium/"+version.Version+"; go-toolkit/"+gv.Version+")")

	auth, ok := a.Authorization[req.URL.Host]
	if !ok {
		auth, ok = a.Authorization["*"]
	}
	if ok && len(auth) > 0 {
		req2.Header.Set("Authorization", auth)
	}

	return a.transport().RoundTrip(req2)
}

func (a *authTransport) transport() http.RoundTripper {
	if a.Transport != nil {
		return a.Transport
	}
	return http.DefaultTransport
}

func newAuthenticatedRoundTripper(authMap map[string]string, whitelist []*url.URL, transport *http.Transport) http.RoundTripper {
	return &authTransport{
		Authorization: authMap,
		Whitelist:     whitelist,
		Transport:     transport,
	}
}
