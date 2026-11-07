//go:build tcp_native && microsandbox_ffi_path && !windows

package ffi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTCPFixtureUsesLoadedImage(t *testing.T) {
	const childEnv = "MSB_TCP_FIXTURE_LOADED_IMAGE_TEST"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTCPFixtureUsesLoadedImage$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("loaded-image subprocess: %v\n%s", err, out)
		}
		return
	}

	// Isolate Load's process-once state, then make the input path unavailable.
	// Fixture symbols must come from the retained real image, not another dlopen.
	library := os.Getenv("MICROSANDBOX_FFI_PATH")
	if library == "" {
		t.Fatal("MICROSANDBOX_FFI_PATH is required for TCP native tests")
	}
	if err := Load(library); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MICROSANDBOX_FFI_PATH", filepath.Join(t.TempDir(), "not-loaded.so"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, fd, err := TCPTestDial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.NewFile(uintptr(fd), "fixture-tcp").Close(); err != nil {
			t.Error(err)
		}
		if acknowledged, err := conn.Abort(ctx); err != nil || !acknowledged {
			t.Errorf("abort fixture connection: acknowledged=%v, err=%v", acknowledged, err)
		}
	}()
	if _, err := conn.Status(); err != nil {
		t.Fatalf("fixture connection must share the production registry: %v", err)
	}
}
