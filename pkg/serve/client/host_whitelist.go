package client

import (
	"net/url"
	"strings"
)

// Check if a URL has a valid match in the whitelist.
// A valid match is when the host (hostname:port) is equal,
// and the URL starts with the (optional) path in the whitelist entry
func validateAgainstWhitelist(url *url.URL, whitelist []*url.URL) bool {
	if len(whitelist) == 0 {
		return true
	}

	for _, u := range whitelist {
		if u.Host != url.Host {
			continue
		}
		if u.Path == "" || strings.HasPrefix(url.Path, u.Path) {
			return true
		}
	}

	return false
}
