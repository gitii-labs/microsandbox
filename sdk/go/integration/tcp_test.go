//go:build integration && microsandbox_ffi_path

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// Larger than the guest's 8 MiB bulk credit window in either direction.
const tcpTransferBytes = 20 << 20

// startGuestServer runs a busybox nc listener inside the guest and waits until it accepts.
func startGuestServer(t *testing.T, ctx context.Context, sb *microsandbox.Sandbox, port uint16, command string) {
	t.Helper()
	if _, err := sb.Shell(ctx, fmt.Sprintf("(%s) >/dev/null 2>&1 &", command)); err != nil {
		t.Fatalf("start guest server on %d: %v", port, err)
	}
	probe := fmt.Sprintf("netstat -ltn | grep -q ':%d '", port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := sb.Shell(ctx, probe)
		if err == nil && out.ExitCode() == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest server on %d never listened", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDialTCP(t *testing.T) {
	ctx := integrationCtx(t)
	sb := newTestSandbox(t)

	startGuestServer(t, ctx, sb, 9001, "nc -lk -p 9001 -e cat")

	t.Run("echo beyond the credit window with a half-close", func(t *testing.T) {
		conn, err := sb.DialTCP(ctx, "127.0.0.1", 9001)
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		payload := randomBytes(t, tcpTransferBytes)
		writeErr := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			if err == nil {
				err = conn.CloseWrite()
			}
			writeErr <- err
		}()
		echoed, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("write: %v", err)
		}
		if !bytes.Equal(echoed, payload) {
			t.Fatalf("echo differs: got %d bytes, want %d", len(echoed), len(payload))
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("concurrent dials", func(t *testing.T) {
		const dials = 8
		var wg sync.WaitGroup
		errs := make(chan error, dials)
		for i := range dials {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := sb.DialTCP(ctx, "127.0.0.1", 9001)
				if err != nil {
					errs <- fmt.Errorf("dial %d: %w", i, err)
					return
				}
				payload := bytes.Repeat([]byte{byte(i)}, 1<<20+i)
				go func() {
					_, _ = conn.Write(payload)
					_ = conn.CloseWrite()
				}()
				echoed, err := io.ReadAll(conn)
				if err == nil && !bytes.Equal(echoed, payload) {
					err = fmt.Errorf("echo %d differs: %d bytes", i, len(echoed))
				}
				errs <- errors.Join(err, conn.Close())
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("orderly close delivers every byte", func(t *testing.T) {
		startGuestServer(t, ctx, sb, 9002, "nc -l -p 9002 > /tmp/close.out")
		conn, err := sb.DialTCP(ctx, "127.0.0.1", 9002)
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		payload := []byte(strings.Repeat("orderly-close\n", 50_000))
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			got, err := sb.FS().Read(ctx, "/tmp/close.out")
			if err == nil && bytes.Equal(got, payload) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("guest received %d of %d bytes (%v)", len(got), len(payload), err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := conn.Write([]byte("late")); err == nil {
			t.Fatal("write after Close succeeded")
		}
	})

	t.Run("a destination that stops reading bounds the writer", func(t *testing.T) {
		startGuestServer(t, ctx, sb, 9003, "nc -l -p 9003 -e sleep 600")
		conn, err := sb.DialTCP(ctx, "127.0.0.1", 9003)
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Write(make([]byte, 256<<20))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write to a stalled destination: n=%d err=%v", n, err)
		}
		// The 8 MiB credit window plus socket buffers on both sides of the guest.
		if n > 48<<20 {
			t.Fatalf("a stalled destination absorbed %d bytes", n)
		}
		t.Logf("a stalled destination stopped the writer after %d bytes", n)
		if err := conn.Abort(); err != nil {
			t.Fatalf("Abort: %v", err)
		}
	})

	t.Run("deadlines", func(t *testing.T) {
		conn, err := sb.DialTCP(ctx, "127.0.0.1", 9001)
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read past the deadline: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
			t.Fatalf("echo after a deadline: %q %v", got, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("a refused port fails the dial", func(t *testing.T) {
		if _, err := sb.DialTCP(ctx, "127.0.0.1", 9); err == nil {
			t.Fatal("dial to a closed port succeeded")
		}
	})

	t.Run("the dial honours its context", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := sb.DialTCP(cancelled, "127.0.0.1", 9001); err == nil {
			t.Fatal("dial with a cancelled context succeeded")
		}
	})
}
