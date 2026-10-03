//go:build integration && microsandbox_ffi_path

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const egressProbe = "nc -z -w 3 1.1.1.1 443 && echo reachable || echo blocked"

// TestCreateFromDiskSnapshotAppliesTheFullConfig boots a disk snapshot through
// CreateSandbox and checks that the creation config reached the new boot: the
// environment, a secret, a bind mount, labels and the network policy, over the
// snapshot's disk.
func TestCreateFromDiskSnapshotAppliesTheFullConfig(t *testing.T) {
	ctx := integrationCtx(t)
	baseName := uniqueIntegrationName(t, "go-sdk-snapcreate-base")
	childName := uniqueIntegrationName(t, "go-sdk-snapcreate-child")
	snapshotName := uniqueIntegrationName(t, "go-sdk-snapcreate")
	t.Cleanup(func() {
		removeSandboxBestEffort(childName)
		removeSandboxBestEffort(baseName)
		removeSnapshotBestEffort(baseName + ":" + snapshotName)
	})

	base, err := createSandbox(t, ctx, baseName,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithRootDisk(microsandbox.RootDisk.Managed(snapshotIntegrationRootDiskSizeMiB)),
	)
	if err != nil {
		t.Fatalf("CreateSandbox base: %v", err)
	}
	// Egress works under the default policy, so the child's "blocked" below is the policy's doing.
	out, err := base.Shell(ctx, egressProbe)
	if err != nil || strings.TrimSpace(out.Stdout()) != "reachable" {
		t.Fatalf("base egress probe = %q, %v", out.Stdout(), err)
	}
	if err := base.FS().Write(ctx, "/root/marker", []byte("from the base")); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := base.Stop(ctx); err != nil {
		t.Fatalf("Stop base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("Close base: %v", err)
	}
	baseHandle, err := microsandbox.GetSandbox(ctx, baseName)
	if err != nil {
		t.Fatalf("GetSandbox base: %v", err)
	}
	artifact, err := baseHandle.Snapshot(ctx, snapshotName)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if artifact.Scope() != microsandbox.SnapshotScopeDisk {
		t.Fatalf("snapshot scope = %q, want disk", artifact.Scope())
	}

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "checkout"), []byte("host file"), 0o644); err != nil {
		t.Fatal(err)
	}
	child, err := createSandbox(t, ctx, childName,
		microsandbox.WithFromSnapshot(artifact),
		microsandbox.WithEnv(map[string]string{"MODE": "resumed"}),
		microsandbox.WithLabels(map[string]string{"topic": "t1"}),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/workspace": microsandbox.Mount.Bind(hostDir, microsandbox.MountOptions{}),
		}),
		microsandbox.WithSecrets(microsandbox.SecretEntry{
			EnvVar:      "API_KEY",
			Value:       "the-real-secret",
			Allow:       []string{"api.example.com"},
			Placeholder: "api-key-placeholder",
		}),
		microsandbox.WithNetwork(microsandbox.NetworkPolicy.None()),
	)
	if err != nil {
		t.Fatalf("CreateSandbox from snapshot: %v", err)
	}
	t.Cleanup(func() { _ = child.Close() })

	marker, err := child.FS().Read(ctx, "/root/marker")
	if err != nil || string(marker) != "from the base" {
		t.Fatalf("snapshot disk marker = %q, %v", marker, err)
	}
	out, err = child.Shell(ctx, `printf '%s|%s|' "$MODE" "$API_KEY"; cat /workspace/checkout`)
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if got := out.Stdout(); got != "resumed|api-key-placeholder|host file" {
		t.Fatalf("guest view = %q", got)
	}
	out, err = child.Shell(ctx, egressProbe)
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if got := strings.TrimSpace(out.Stdout()); got != "blocked" {
		t.Fatalf("NetworkPolicy.None left egress %s", got)
	}
	handle, err := microsandbox.GetSandbox(ctx, childName)
	if err != nil {
		t.Fatalf("GetSandbox child: %v", err)
	}
	config, err := handle.Config()
	if err != nil {
		t.Fatalf("child config: %v", err)
	}
	if got := config.Labels["topic"]; got != "t1" {
		t.Fatalf("label topic = %q", got)
	}
}
