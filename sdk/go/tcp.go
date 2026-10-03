package microsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ErrTCPCleanupUnknown is returned by TCPConn.Close and TCPConn.Abort when the
// guest did not confirm, in time, that it released the connection's socket.
// The guest socket may still be open.
var ErrTCPCleanupUnknown = errors.New("microsandbox: guest did not confirm the TCP connection's release")

// TCPConn is a TCP connection opened from inside the guest. It implements
// net.Conn, including deadlines, plus CloseWrite and Abort.
//
// Both directions are bounded: the guest admits written bytes only up to the
// credit it granted, and returns credit for received bytes only as Read takes
// them. Call Close or Abort to release the connection; one that becomes
// unreachable first is aborted.
type TCPConn struct {
	conn   *net.UnixConn
	native *ffi.TCPConn
	remote tcpAddr
	once   sync.Once
	err    error
}

type tcpAddr struct{ host, port string }

func (a tcpAddr) Network() string { return "tcp" }
func (a tcpAddr) String() string  { return net.JoinHostPort(a.host, a.port) }

// DialTCP opens a TCP connection from inside the guest to host:port. The guest
// resolves host. ctx bounds the dial only.
func (s *Sandbox) DialTCP(ctx context.Context, host string, port uint16) (*TCPConn, error) {
	native, fd, err := s.inner.DialTCP(ctx, host, port)
	if err != nil {
		return nil, wrapFFI(err)
	}
	file := os.NewFile(uintptr(fd), "guest-tcp")
	conn, err := net.FileConn(file)
	// FileConn holds its own descriptor; this one has served its purpose.
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_, abortErr := native.Abort(context.Background())
		return nil, errors.Join(fmt.Errorf("microsandbox: guest TCP socket: %w", err), abortErr)
	}
	c := &TCPConn{
		conn:   conn.(*net.UnixConn),
		native: native,
		remote: tcpAddr{host: host, port: strconv.Itoa(int(port))},
	}
	// A connection dropped without Close or Abort is aborted, never finished: an
	// unreachable owner cannot vouch that it wrote everything it meant to.
	runtime.SetFinalizer(c, func(c *TCPConn) { go func() { _ = c.Abort() }() })
	return c, nil
}

// Read reads bytes the destination sent. It returns io.EOF once the destination
// ended its side in order, and an error if the guest connection failed first.
func (c *TCPConn) Read(p []byte) (int, error) {
	n, err := c.conn.Read(p)
	if errors.Is(err, io.EOF) {
		if status, statusErr := c.native.Status(); statusErr == nil && status.ReadError != nil {
			return n, fmt.Errorf("microsandbox: guest TCP read: %s", *status.ReadError)
		}
	}
	return n, err
}

// Write writes bytes to the destination, blocking while the guest withholds credit.
func (c *TCPConn) Write(p []byte) (int, error) {
	n, err := c.conn.Write(p)
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		if status, statusErr := c.native.Status(); statusErr == nil && status.WriteError != nil {
			return n, fmt.Errorf("microsandbox: guest TCP write: %s", *status.WriteError)
		}
	}
	return n, err
}

// CloseWrite half-closes the connection: the destination sees end of stream
// after every byte written before it, and Read continues until the destination
// ends its side.
func (c *TCPConn) CloseWrite() error {
	// Announce the half-close first: an unannounced end of stream aborts.
	if err := c.native.Finish(); err != nil {
		return wrapFFI(err)
	}
	return c.conn.CloseWrite()
}

// Close closes the connection in order: every byte written is delivered to the
// destination, the stream is finished, and the guest connection is released
// without a reset. When the guest stops accepting bytes for longer than an idle
// bound, the connection is aborted instead and Close returns an error, as it
// does when any written byte did not reach the destination. It returns
// ErrTCPCleanupUnknown when the guest did not confirm the release.
func (c *TCPConn) Close() error {
	return c.release(func() (bool, error) {
		// The native side delivers what it reads up to this end of stream, then finishes.
		finishErr := c.native.Finish()
		if finishErr == nil {
			finishErr = c.conn.CloseWrite()
		}
		if finishErr != nil {
			acknowledged, err := c.native.Abort(context.Background())
			return acknowledged, errors.Join(finishErr, wrapFFI(err), c.conn.Close())
		}
		acknowledged, err := c.native.Close(context.Background())
		return acknowledged, errors.Join(wrapFFI(err), c.conn.Close())
	})
}

// Abort discards unwritten bytes and resets the destination. It returns
// ErrTCPCleanupUnknown when the guest did not confirm the release.
func (c *TCPConn) Abort() error {
	return c.release(func() (bool, error) {
		// Close the socket first so blocked calls end with net.ErrClosed. Its unannounced end
		// of stream aborts the native side too; Abort then waits for the guest's release.
		socketErr := c.conn.Close()
		acknowledged, err := c.native.Abort(context.Background())
		return acknowledged, errors.Join(socketErr, wrapFFI(err))
	})
}

func (c *TCPConn) release(release func() (bool, error)) error {
	c.once.Do(func() {
		runtime.SetFinalizer(c, nil)
		acknowledged, err := release()
		if err == nil && !acknowledged {
			err = ErrTCPCleanupUnknown
		}
		c.err = err
	})
	return c.err
}

// LocalAddr returns the local end of the socket pair that carries the bytes.
func (c *TCPConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the destination as dialed.
func (c *TCPConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the read and write deadlines.
func (c *TCPConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline sets the deadline for Read.
func (c *TCPConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for Write.
func (c *TCPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
