//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// A fast line-buffered writer can exit while its final PTY output is still
// queued. Each transfer must retain the whole payload before reporting success.
func TestExecTTYDrainsOutputBeforeExit(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	const transfers = 100
	payload := strings.Repeat("PTY output must arrive before the exit event.\n", 512)
	const guestFile = "/tmp/exec-tty-output"
	prepared, err := sb.Shell(ctx, `printf %s "$OUTPUT" > `+guestFile,
		microsandbox.WithExecEnv(map[string]string{"OUTPUT": payload}))
	if err != nil {
		t.Fatalf("prepare guest fixture: %v", err)
	}
	if prepared.ExitCode() != 0 {
		t.Fatalf("prepare guest fixture exit %d: %s", prepared.ExitCode(), prepared.Stderr())
	}
	for transfer := range transfers {
		if !t.Run(strconv.Itoa(transfer), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			out, err := sb.Exec(ctx, "sh", []string{"-c", `stty -opost; exec head -c "$OUTPUT_BYTES" ` + guestFile},
				microsandbox.WithExecTTY(true),
				microsandbox.WithExecEnv(map[string]string{"OUTPUT_BYTES": strconv.Itoa(len(payload))}))
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if out.ExitCode() != 0 {
				t.Fatalf("guest exit %d: %s", out.ExitCode(), out.Stderr())
			}
			if got := out.Stdout(); got != payload {
				t.Fatalf("received %d of %d expected bytes", len(got), len(payload))
			}
		}) {
			t.FailNow()
		}
	}
}
