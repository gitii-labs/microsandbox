//go:build oauth_compat && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run separately for each native library; the FFI loader retains its first image.
func TestOAuthOmissionRefusesOlderPeer(t *testing.T) {
	setupNative(t)
	home := os.Getenv("MSB_HOME")
	if home == "" {
		t.Fatal("set MSB_HOME to an isolated test directory")
	}
	rootfs := filepath.Join(home, "fixture-root")
	if err := os.MkdirAll(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	grant := OAuthSecretConfig{
		BrokerEndpoint:          filepath.Join(home, "fixture.sock"),
		GrantID:                 "synthetic",
		TokenEndpoint:           "https://provider.invalid/token",
		InjectHosts:             []string{"provider.invalid"},
		AccessTokenField:        "access_token",
		RefreshTokenField:       "refresh_token",
		AccessEnvVar:            "ACCESS",
		RefreshEnvVar:           "REFRESH",
		AccessSentinel:          "$ACCESS",
		RefreshSentinel:         "$REFRESH",
		OmitTokenResponseFields: []string{"id_token"},
	}
	peer := os.Getenv("MSB_TEST_OAUTH_OLD_PEER")
	var want string
	switch peer {
	case "ffi":
		want = "update the native SDK"
	case "runtime":
		want = "upgrade msb"
	default:
		t.Fatal("set MSB_TEST_OAUTH_OLD_PEER to ffi or runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sb, err := CreateSandbox(ctx, "oauth-omission-compat",
		WithBindRootfs(rootfs), WithOAuthSecrets(grant))
	if sb != nil {
		sb.Close()
		t.Fatal("an unsupported omission policy started a sandbox")
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want an error containing %q", err, want)
	}
	if peer == "ffi" && !IsKind(err, ErrUnsupportedOperation) {
		t.Fatalf("got %v, want ErrUnsupportedOperation", err)
	}
}
