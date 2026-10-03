package microsandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallDir_HonorsMSBHome(t *testing.T) {
	// MSB_HOME set: used as-is, matching resolve_home().
	t.Setenv("MSB_HOME", filepath.Join(t.TempDir(), "custom"))
	want := os.Getenv("MSB_HOME")
	got, err := installDir()
	if err != nil {
		t.Fatalf("installDir() error = %v", err)
	}
	if got != want {
		t.Fatalf("installDir() with MSB_HOME = %q, want %q", got, want)
	}

	// MSB_HOME unset: falls back to ~/.microsandbox (unchanged default).
	if err := os.Unsetenv("MSB_HOME"); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	got, err = installDir()
	if err != nil {
		t.Fatalf("installDir() error = %v", err)
	}
	if want := filepath.Join(home, ".microsandbox"); got != want {
		t.Fatalf("installDir() without MSB_HOME = %q, want %q", got, want)
	}
}

func TestSandboxLogRoot(t *testing.T) {
	t.Run("configured home", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("MSB_HOME", home)

		got, err := SandboxLogRoot()
		if err != nil {
			t.Fatalf("SandboxLogRoot: %v", err)
		}
		if want := filepath.Join(home, "sandboxes"); got != want {
			t.Errorf("SandboxLogRoot = %q, want %q", got, want)
		}
	})

	t.Run("operator home", func(t *testing.T) {
		// An empty MSB_HOME is unset, as the runtime's resolve_home treats it.
		t.Setenv("MSB_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)

		got, err := SandboxLogRoot()
		if err != nil {
			t.Fatalf("SandboxLogRoot: %v", err)
		}
		if want := filepath.Join(home, ".microsandbox", "sandboxes"); got != want {
			t.Errorf("SandboxLogRoot = %q, want %q", got, want)
		}
	})
}
