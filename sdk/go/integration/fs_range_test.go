//go:build integration && microsandbox_ffi_path

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestFsReadRangeStream(t *testing.T) {
	ctx := integrationCtx(t)
	dir := t.TempDir()
	data := bytes.Repeat([]byte("0123456789abcdef"), 128*1024)
	path := filepath.Join(dir, "range.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	modified := time.Unix(1700000000, 123456789)
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	host, err := os.Stat(path)
	if err != nil || !host.ModTime().Equal(modified) {
		t.Fatalf("host timestamp precondition: %v, %v", host, err)
	}
	sb, err := createSandbox(t, ctx, "go-fs-range", microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/range": microsandbox.Mount.Bind(dir, microsandbox.MountOptions{Readonly: true}),
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := sb.Stop(cleanup); err != nil {
			t.Error(err)
		}
		if err := sb.Close(); err != nil {
			t.Error(err)
		}
	})
	fs := sb.FS()
	for _, tc := range []struct {
		name           string
		offset, length uint64
	}{
		{"middle", 37, 512*1024 + 11},
		{"ending-at-eof", uint64(len(data)) - 12345, 12345},
		{"zero-length", 37, 0},
		{"at-eof", uint64(len(data)), 100},
		{"beyond-eof", uint64(len(data)) + 100, 100},
		{"past-eof", uint64(len(data)) - 31, 100},
		{"maximum-offset", ^uint64(0), 1},
		{"zero-at-maximum-offset", ^uint64(0), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := fs.ReadRangeStream(ctx, "/range/range.bin", tc.offset, tc.length)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			n, readErr := stream.CopyTo(ctx, &got)
			closeErr := stream.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read: %v; close: %v", readErr, closeErr)
			}
			start := min(tc.offset, uint64(len(data)))
			end := min(start+tc.length, uint64(len(data)))
			want := data[start:end]
			if n != int64(len(want)) || !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("range [%d,%d): got %d bytes, want %d exact bytes", tc.offset, tc.offset+tc.length, n, len(want))
			}
		})
	}
	st, err := fs.Stat(ctx, "/range/range.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime.Equal(modified) || st.Inode == 0 || st.Size != int64(len(data)) {
		t.Fatalf("incorrect stat: %+v, want mtime %v", st, modified)
	}
	result, err := sb.Exec(ctx, "stat", []string{"-c", "%i", "/range/range.bin"})
	if err != nil || !result.Success() {
		t.Fatalf("guest stat: %v, %v", result, err)
	}
	inode, err := strconv.ParseUint(strings.TrimSpace(result.Stdout()), 10, 64)
	if err != nil || inode != st.Inode {
		t.Fatalf("inode: SDK %d, guest %d (%v)", st.Inode, inode, err)
	}
}
