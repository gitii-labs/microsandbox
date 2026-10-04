//go:build tcp_native && microsandbox_ffi_path && !windows

package ffi

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestTCPDialCancellationReclaimsSuccessfulResult(t *testing.T) {
	for _, resultReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-before-result", true: "ready-result-with-cancel"}[resultReady], func(t *testing.T) {
			ctx, timeout := context.WithTimeout(context.Background(), 5*time.Second)
			defer timeout()
			out, err := fixtureDialResult(ctx)
			if err != nil {
				t.Fatal(err)
			}
			conn, fd, err := parseTCPDial(out)
			if err != nil {
				t.Fatal(err)
			}
			var stat syscall.Stat_t
			if err := syscall.Fstat(fd, &stat); err != nil {
				t.Fatalf("dial descriptor must be open: %v", err)
			}
			if _, err := conn.Status(); err != nil {
				t.Fatalf("dial handle must be registered: %v", err)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			done := make(chan callResult, 1)
			if resultReady {
				done <- callResult{out: out}
			}
			result, err := awaitCall(cancelled, done, func() {
				if !resultReady {
					done <- callResult{out: out}
				}
			}, cleanupTCPDial)
			if result != "" || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled dial = %q, %v", result, err)
			}
			// Only cancellation, no cleanup error: the late credit still led to acknowledgement.
			if err.Error() != context.Canceled.Error() {
				t.Fatalf("cleanup failed: %v", err)
			}
			if err := syscall.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
				t.Fatalf("cancelled dial descriptor leaked: %v", err)
			}
			if _, err := conn.Status(); err == nil {
				t.Fatal("cancelled dial native handle leaked")
			}
			if err := conn.TestEvent(ctx, TCPTestWaitCancel); err != nil {
				t.Fatalf("guest cancellation: %v", err)
			}
			if err := conn.TestEvent(ctx, TCPTestWaitDisconnect); err != nil {
				t.Fatalf("relay/agent connection leaked: %v", err)
			}
		})
	}
}
