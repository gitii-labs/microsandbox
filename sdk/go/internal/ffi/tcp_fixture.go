//go:build tcp_native && microsandbox_ffi_path && !windows

package ffi

/*
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef char *(*test_dial_fn)(uint64_t, uint8_t *, size_t);
typedef char *(*test_event_fn)(uint64_t, uint64_t, uint8_t, uint8_t *, size_t);

static char *test_tcp_dial(void *fn, uint64_t cancel, uint8_t *buf, size_t len) {
    return ((test_dial_fn)fn)(cancel, buf, len);
}
static char *test_tcp_event(void *fn, uint64_t cancel, uint64_t conn, uint8_t event, uint8_t *buf, size_t len) {
    return ((test_event_fn)fn)(cancel, conn, event, buf, len);
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"unsafe"
)

// Test-agent commands. The opt-in Rust fixture defines the other side of this test contract.
const (
	TCPTestGuestReset                uint8 = 1
	TCPTestUnexpectedControl         uint8 = 2
	TCPTestOrderedEOF                uint8 = 3
	TCPTestInvalidCredit             uint8 = 4
	TCPTestInvalidRecord             uint8 = 5
	TCPTestDisconnect                uint8 = 6
	TCPTestDisconnectOnCancel        uint8 = 7
	TCPTestGuestFailureWithoutCancel uint8 = 8
	TCPTestWaitInput                 uint8 = 10
	TCPTestWaitFinish                uint8 = 11
	TCPTestWaitCancel                uint8 = 12
	TCPTestWaitDisconnect            uint8 = 13
)

func tcpFixtureSymbol(name string) (unsafe.Pointer, error) {
	library := os.Getenv("MICROSANDBOX_FFI_PATH")
	if library == "" {
		return nil, fmt.Errorf("MICROSANDBOX_FFI_PATH is required for TCP native tests")
	}
	// Load this exact image, rather than an SDK-materialized copy with an independent registry.
	if err := Load(library); err != nil {
		return nil, err
	}
	path := C.CString(library)
	defer C.free(unsafe.Pointer(path))
	handle := C.dlopen(path, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		return nil, fmt.Errorf("load TCP test fixture: %s", C.GoString(C.dlerror()))
	}
	defer C.dlclose(handle)
	symbol := C.CString(name)
	defer C.free(unsafe.Pointer(symbol))
	fn := C.dlsym(handle, symbol)
	if fn == nil {
		return nil, fmt.Errorf("TCP native library must be built with tcp-test-fixture: %s", C.GoString(C.dlerror()))
	}
	return fn, nil // ensureLoaded keeps this same library loaded for the process lifetime.
}

func fixtureDialResult(ctx context.Context) (string, error) {
	fn, err := tcpFixtureSymbol("msb_test_tcp_dial")
	if err != nil {
		return "", err
	}
	return callBufCleanup(ctx, defaultBufSize, func(cancel C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.test_tcp_dial(fn, cancel, buf, size)
	}, cleanupTCPDial)
}

// TCPTestDial uses a real loopback test agent and the production native relay registration.
func TCPTestDial(ctx context.Context) (*TCPConn, int, error) {
	out, err := fixtureDialResult(ctx)
	if err != nil {
		return nil, -1, err
	}
	return parseTCPDial(out)
}

// TestEvent sends or awaits an event on the loopback test agent; see its Rust fixture.
func (c *TCPConn) TestEvent(ctx context.Context, event uint8) error {
	fn, err := tcpFixtureSymbol("msb_test_tcp_event")
	if err != nil {
		return err
	}
	_, err = call(ctx, func(cancel C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.test_tcp_event(fn, cancel, c.handle, C.uint8_t(event), buf, size)
	})
	return err
}
