//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestMountWriteNotificationsWithHeldDescriptor keeps one UID-1000 guest fd
// open across two separately observed mutations. FIFO barriers never close or
// fsync it, and the host waits on actual runtime events rather than a scan timer.
func TestMountWriteNotificationsWithHeldDescriptor(t *testing.T) {
	ctx, cancel := context.WithCancel(integrationCtx(t))
	defer cancel()
	name := "go-sdk-held-mount-writes"
	host := canonicalTempDir(t)
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/mnt/distributed": microsandbox.Mount.Table(microsandbox.MountTableChild{
				Name: "work", Host: host, StatVirtualization: microsandbox.StatVirtualizationRelaxed,
				HostPermissions: microsandbox.HostPermissionsMirror,
				Owner:           &microsandbox.MountOwner{UID: 1000, GID: 1000},
			}),
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		if err := sb.Stop(cleanup); err != nil {
			t.Error(err)
		}
		if err := sb.Close(); err != nil {
			t.Error(err)
		}
		if err := microsandbox.RemoveSandbox(cleanup, name); err != nil {
			t.Error(err)
		}
	})
	initial, err := sb.WatchMountWrites(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !initial.Reset || initial.Cursor.Epoch == "" || initial.Cursor.Revision == 0 || len(initial.Mounts) != 1 || initial.Mounts[0].Name != "work" || initial.Mounts[0].Attachment == 0 || initial.Mounts[0].Revision != 0 {
		t.Fatalf("initial mutation state: %+v", initial)
	}
	shell := func(command string) {
		t.Helper()
		out, err := sb.Shell(ctx, command)
		if err != nil {
			t.Fatal(err)
		}
		if !out.Success() {
			t.Fatalf("%s: %s%s", command, out.Stdout(), out.Stderr())
		}
	}
	shell("mkdir /tmp/mount-proof; chmod 0777 /tmp/mount-proof; mkfifo /tmp/mount-proof/next /tmp/mount-proof/release; chmod 0666 /tmp/mount-proof/next /tmp/mount-proof/release")
	finished := make(chan error, 1)
	go func() {
		out, err := sb.Exec(ctx, "/bin/sh", []string{"-c", "set -eu; test $(id -u) = 1000; test $(id -g) = 1000; exec 3>/mnt/distributed/work/note; printf one >&3; read next </tmp/mount-proof/next; printf two >&3; read release </tmp/mount-proof/release"}, microsandbox.WithExecUser("1000:1000"))
		if err == nil && !out.Success() {
			err = fmt.Errorf("held writer: %s%s", out.Stdout(), out.Stderr())
		}
		finished <- err
	}()
	cursor := initial.Cursor
	await := func(want string) {
		t.Helper()
		for {
			next, err := sb.WatchMountWrites(ctx, &cursor)
			if err != nil {
				t.Fatal(err)
			}
			if next.Reset || next.Cursor.Epoch != initial.Cursor.Epoch || next.Cursor.Revision <= cursor.Revision || len(next.Mounts) != 1 || next.Mounts[0].Name != "work" || next.Mounts[0].Attachment != initial.Mounts[0].Attachment || next.Mounts[0].Revision == 0 {
				t.Fatalf("mutation identity changed: %+v", next)
			}
			cursor = next.Cursor
			data, err := os.ReadFile(filepath.Join(host, "note"))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) == want {
				break
			}
		}
		select {
		case err := <-finished:
			t.Fatalf("writer closed before %q was observed: %v", want, err)
		default:
		}
	}
	await("one")
	shell("printf 'next\\n' >/tmp/mount-proof/next")
	await("onetwo")
	shell("printf 'release\\n' >/tmp/mount-proof/release")
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// TestMountTableLiveChanges drives a mount table through the Go SDK: a launch
// child, a live attach, a read-only switch, a detach and a file child with an
// owner, each observed from inside the guest without a restart.
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
				Name: "launch", Host: launch, HostPermissions: microsandbox.HostPermissionsMirror,
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
	mustShell("chmod 0750 /mnt/distributed/launch/file")
	if info, err := os.Stat(filepath.Join(launch, "file")); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("mirrored host mode: %v %v", info.Mode(), err)
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
	// A file child with an owner: the host file shows as the owner, and a
	// file the host renames into place shows at the guest's next open.
	item := filepath.Join(canonicalTempDir(t), "item")
	if err := os.WriteFile(item, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sb.AttachMount(ctx, microsandbox.MountTableChild{
		Name: "item", Host: item, StatVirtualization: microsandbox.StatVirtualizationRelaxed,
		Owner: &microsandbox.MountOwner{UID: 2000, GID: 2001},
	}); err != nil {
		t.Fatalf("AttachMount file child: %v", err)
	}
	if got := mustShell("stat -c '%F %u:%g' /mnt/distributed/item"); got != "regular file 2000:2001" {
		t.Fatalf("file child stat = %q", got)
	}
	staged := item + ".staged"
	if err := os.WriteFile(staged, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, item); err != nil {
		t.Fatal(err)
	}
	if got := mustShell("cat /mnt/distributed/item"); got != "second" {
		t.Fatalf("file child content after rename = %q", got)
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
