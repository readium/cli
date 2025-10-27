package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"syscall"
	"time"
)

// Code below mostly from https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang

func safeSocketControl(network string, address string, conn syscall.RawConn) error {
	if !(network == "tcp4" || network == "tcp6") {
		return fmt.Errorf("%s is not a safe network type", network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s is not a valid host/port pair: %s", address, err)
	}

	ipaddress := net.ParseIP(host)
	if ipaddress == nil {
		return fmt.Errorf("%s is not a valid IP address", host)
	}

	if !isPublicIPAddress(ipaddress) {
		return fmt.Errorf("%s is not a public IP address", ipaddress)
	}

	if !(port == "80" || port == "443") {
		return fmt.Errorf("%s is not a safe port number", port)
	}

	return nil
}

// Some of the below conf values from https://github.com/imgproxy/imgproxy/blob/master/transport/transport.go

const ClientKeepAliveTimeout = 90  // Imgproxy default
var Workers = runtime.NumCPU() * 2 // Imgproxy default

func NewHTTPClient(auth string, whitelist []*url.URL, bypassSafeSocketControl bool) (*http.Client, error) {
	safeDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
		Control:   safeSocketControl,
	}
	if bypassSafeSocketControl {
		safeDialer.Control = nil
	}

	safeTransport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         safeDialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: Workers + 1,
		IdleConnTimeout:     time.Duration(ClientKeepAliveTimeout) * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: newAuthenticatedRoundTripper(auth, whitelist, safeTransport),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				// Default Go behavior
				return errors.New("stopped after 10 redirects")
			}

			if !validateAgainstWhitelist(req.URL, whitelist) {
				return fmt.Errorf("redirect to %s is not allowed by the whitelist", req.URL)
			}
			return nil
		},
	}, nil
}
