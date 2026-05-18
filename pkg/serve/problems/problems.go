// Package problems defines the application/problem+json (RFC 9457) types
// returned by the serve API and helpers for converting raw errors into them.
package problems

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"syscall"

	"github.com/airmrcr/go-problem"
	"github.com/readium/cli/pkg/serve/session"
	"github.com/readium/go-toolkit/pkg/fetcher"
)

// Write writes err to w as an application/problem+json response. If err already
// contains a *problem.Problem in its tree it's used directly; otherwise From
// builds one. The library's internal logger is suppressed — callers should log
// at the call site (typically via slog) if they want a log line.
//
// If writing the response body itself fails (e.g. client disconnected
// mid-write), the write error is logged here — by that point the status line
// and headers are already on the wire, so there is no way to recover. Client
// disconnect errors (EPIPE/ECONNRESET) are ignored as expected noise.
func Write(err error, w http.ResponseWriter, r *http.Request) {
	werr := problem.WriteError(err, w, r, From, problem.WriteOptions{LogDisabled: true})
	if werr == nil {
		return
	}
	if errors.Is(werr, syscall.EPIPE) || errors.Is(werr, syscall.ECONNRESET) {
		return
	}
	slog.ErrorContext(r.Context(), "failed writing problem response", "error", werr)
}

// genericInternalDetail is the only detail string ever sent to clients for
// InternalServerError problems. The specific cause is preserved on the
// problem's wrapped error so it reaches logs but not the response body.
const genericInternalDetail = "An internal error occurred"

const (
	publicationServerBase = "https://readium.org/publication-server/error/"
	readingSessionBase    = "https://readium.org/reading-session/error/"
)

var (
	InternalServerError = problem.Type{
		URI:    publicationServerBase + "internal",
		Status: http.StatusInternalServerError,
		Title:  "Internal Server Error",
	}
	BadRequest = problem.Type{
		URI:    publicationServerBase + "bad-request",
		Status: http.StatusBadRequest,
		Title:  "Bad Request",
	}
	NotFound = problem.Type{
		URI:    publicationServerBase + "not-found",
		Status: http.StatusNotFound,
		Title:  "Not Found",
	}
	Forbidden = problem.Type{
		URI:    publicationServerBase + "forbidden",
		Status: http.StatusForbidden,
		Title:  "Forbidden",
	}
	BadGateway = problem.Type{
		URI:    publicationServerBase + "bad-gateway",
		Status: http.StatusBadGateway,
		Title:  "Bad Gateway",
	}
	NotImplemented = problem.Type{
		URI:    publicationServerBase + "not-implemented",
		Status: http.StatusNotImplemented,
		Title:  "Not Implemented",
	}
	RangeNotSatisfiable = problem.Type{
		URI:    publicationServerBase + "range-not-satisfiable",
		Status: http.StatusRequestedRangeNotSatisfiable,
		Title:  "Range Not Satisfiable",
	}
	ServiceUnavailable = problem.Type{
		URI:    publicationServerBase + "service-unavailable",
		Status: http.StatusServiceUnavailable,
		Title:  "Service Unavailable",
	}
	Gone = problem.Type{
		URI:    publicationServerBase + "gone",
		Status: http.StatusGone,
		Title:  "Gone",
	}

	ReadingSessionRevoked = problem.Type{
		URI:    readingSessionBase + "revoked",
		Status: http.StatusForbidden,
		Title:  "Reading session revoked",
	}
	ReadingSessionReturned = problem.Type{
		URI:    readingSessionBase + "returned",
		Status: http.StatusForbidden,
		Title:  "Reading session returned",
	}
	ReadingSessionCancelled = problem.Type{
		URI:    readingSessionBase + "cancelled",
		Status: http.StatusForbidden,
		Title:  "Reading session cancelled",
	}
	ReadingSessionExpired = problem.Type{
		URI:    readingSessionBase + "expired",
		Status: http.StatusGone,
		Title:  "Reading session expired",
	}
	DeviceLimitExceeded = problem.Type{
		URI:    readingSessionBase + "device-limit-exceeded",
		Status: http.StatusTooManyRequests,
		Title:  "Device limit exceeded",
	}
)

// Internal returns an InternalServerError problem. The msg and (optional)
// wrapped err are preserved on the problem's internal error chain so they
// reach logs via Problem.Error(), but the client only ever sees the generic
// detail.
func Internal(msg string, err error) *problem.Problem {
	var wrapped error
	switch {
	case msg != "" && err != nil:
		wrapped = fmt.Errorf("%s: %w", msg, err)
	case msg != "":
		wrapped = errors.New(msg)
	case err != nil:
		wrapped = err
	}
	b := InternalServerError.Build()
	if wrapped != nil {
		b = b.Wrap(wrapped)
	}
	return b.Detail(genericInternalDetail).Problem()
}

// From maps a raw error to a *problem.Problem suitable for use as the fallback
// constructor passed to problem.WriteError. If the error tree already contains
// a *problem.Problem it is returned unchanged. Known sentinel errors are mapped
// to specific types; anything else becomes an InternalServerError with a
// generic detail (the original error is wrapped for logs only).
func From(err error) *problem.Problem {
	if err == nil {
		return nil
	}
	if p, ok := problem.As(err); ok {
		return p
	}

	switch {
	case errors.Is(err, session.ErrReadingSessionRevoked):
		return ReadingSessionRevoked.Build().Wrap(err).Detail(err.Error()).Problem()
	case errors.Is(err, session.ErrReadingSessionReturned):
		return ReadingSessionReturned.Build().Wrap(err).Detail(err.Error()).Problem()
	case errors.Is(err, session.ErrReadingSessionCancelled):
		return ReadingSessionCancelled.Build().Wrap(err).Detail(err.Error()).Problem()
	case errors.Is(err, session.ErrReadingSessionExpired):
		return ReadingSessionExpired.Build().Wrap(err).Detail(err.Error()).Problem()
	}

	return Internal("", err)
}

// FromResourceError converts a fetcher.ResourceError to a Problem, picking the
// appropriate type from its HTTP status. The ResourceError is wrapped so its
// cause stays inspectable via errors.Is/As, but the client-facing detail is a
// fixed per-status string — the cause's text (which may include filesystem
// paths or upstream error specifics) is never serialized.
func FromResourceError(rerr *fetcher.ResourceError) *problem.Problem {
	if rerr == nil {
		return nil
	}
	switch rerr.HTTPStatus() {
	case http.StatusNotFound:
		return NotFound.Build().Wrap(rerr).Detail("Resource not found").Problem()
	case http.StatusForbidden:
		return Forbidden.Build().Wrap(rerr).Detail("Access to resource is forbidden").Problem()
	case http.StatusRequestedRangeNotSatisfiable:
		return RangeNotSatisfiable.Build().Wrap(rerr).Detail("Requested range is not satisfiable").Problem()
	case http.StatusServiceUnavailable:
		return ServiceUnavailable.Build().Wrap(rerr).Detail("Resource is temporarily unavailable").Problem()
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return BadGateway.Build().Wrap(rerr).Detail("Upstream resource fetch failed").Problem()
	default:
		return Internal("", rerr)
	}
}
