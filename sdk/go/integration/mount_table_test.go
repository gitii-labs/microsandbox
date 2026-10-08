//go:build integration && microsandbox_ffi_path

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestMountTableLiveChanges drives a mount table through the Go SDK: a launch
// child, a live attach, a read-only switch and a detach, each observed from
// inside the guest without a restart.
func TestMountTableLiveChanges(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-mount-table"
	launch := canonicalTempDir(t)
	attached := canonicalTempDir(t)
	if err := os.WriteFile(filepath.Join(attached, "note"), []byte("attached"), 0o644); err != nil {
		t.Fatal(err)
	}

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/mnt/distributed": microsandbox.Mount.Table(microsandbox.MountTableChild{
				Name: "launch", Host: launch,
			}),
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Stop(ctx); _ = sb.Close(); _ = microsandbox.RemoveSandbox(ctx, name) }()

	shell := func(script string) (bool, string) {
		t.Helper()
		out, err := sb.Shell(ctx, script)
		if err != nil {
			t.Fatalf("shell %q: %v", script, err)
		}
		return out.Success(), strings.TrimSpace(out.Stdout() + out.Stderr())
	}
	mustShell := func(script string) string {
		t.Helper()
		ok, output := shell(script)
		if !ok {
			t.Fatalf("guest command %q failed: %s", script, output)
		}
		return output
	}

	mustShell("echo from-guest > /mnt/distributed/launch/file")
	if got, _ := os.ReadFile(filepath.Join(launch, "file")); string(got) != "from-guest\n" {
		t.Fatalf("host file = %q", got)
	}

	if err := sb.AttachMount(ctx, microsandbox.MountTableChild{
		Name: "attached", Host: attached, Cache: microsandbox.MountTableCacheNever,
	}); err != nil {
		t.Fatalf("AttachMount: %v", err)
	}
	if got := mustShell("ls /mnt/distributed"); got != "attached\nlaunch" {
		t.Fatalf("listing after attach = %q", got)
	}
	if got := mustShell("cat /mnt/distributed/attached/note"); got != "attached" {
		t.Fatalf("attached content = %q", got)
	}

	if err := sb.SetMountReadonly(ctx, "launch", true); err != nil {
		t.Fatalf("SetMountReadonly: %v", err)
	}
	if ok, output := shell("echo x > /mnt/distributed/launch/other"); ok || !strings.Contains(output, "Read-only file system") {
		t.Fatalf("write to a read-only child: ok=%v output=%q", ok, output)
	}

	if err := sb.DetachMount(ctx, "attached"); err != nil {
		t.Fatalf("DetachMount: %v", err)
	}
	if got := mustShell("ls /mnt/distributed"); got != "launch" {
		t.Fatalf("listing after detach = %q", got)
	}
	if err := sb.DetachMount(ctx, "attached"); err == nil {
		t.Fatal("detaching a missing child must fail")
	}
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
