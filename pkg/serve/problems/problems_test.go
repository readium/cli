package problems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsClientDisconnect(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		// The server cancels the request context when the client goes away;
		// for HTTP/2 it does so before failing the handler's Write, so aborted
		// streams are recognized by the context alone, whatever the error says.
		{"http2 stream reset", canceled, errors.New("http2: stream closed"), true},
		{"http2 connection gone", canceled, errors.New("client disconnected"), true},
		{"canceled request, any error", canceled, errors.New("something broke"), true},
		// HTTP/1 writes can fail before the background read notices the
		// disconnect and cancels the context.
		{"broken pipe", t.Context(), &net.OpError{Op: "write", Err: os.NewSyscallError("write", syscall.EPIPE)}, true},
		{"connection reset", t.Context(), &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, true},
		{"canceled read mid-stream", t.Context(), fmt.Errorf("reading range: %w", context.Canceled), true},
		// Failures on a live request must still be logged, including upstream
		// (origin) HTTP/2 errors that merely sound like client aborts.
		{"upstream http2 stream error", t.Context(), errors.New("stream error: stream ID 5; INTERNAL_ERROR; received from peer"), false},
		{"upstream connection lost", t.Context(), errors.New("http2: client connection lost"), false},
		{"deadline exceeded", t.Context(), context.DeadlineExceeded, false},
		{"generic error", t.Context(), errors.New("something broke"), false},
		{"no error", t.Context(), nil, false},
		{"nil context, generic error", nil, errors.New("something broke"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, IsClientDisconnect(c.ctx, c.err))
		})
	}
}
