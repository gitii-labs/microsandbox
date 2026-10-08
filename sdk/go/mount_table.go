package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// MountTableCache selects guest caching for one mount-table child.
type MountTableCache string

const (
	// MountTableCacheAuto lets the guest kernel cache data, entries and
	// attributes. It is the zero value's meaning.
	MountTableCacheAuto MountTableCache = "auto"
	// MountTableCacheNever uses direct I/O and zero entry and attribute
	// timeouts, for content that must not linger in guest memory, such as
	// secrets.
	MountTableCacheNever MountTableCache = "never"
)

// MountTableChild is one child of a mount table: a guest-visible name over a
// host directory.
type MountTableChild struct {
	// Name is the guest-visible name, one path component, unique within the
	// table.
	Name string
	// Host is the absolute host directory. No path component may be a
	// symlink; resolve a symlinked prefix such as /var on macOS first.
	Host string
	// Readonly refuses every guest mutation, including writes through files
	// the guest opened before the child became read-only.
	Readonly bool
	// QuotaBytes bounds guest writes to the directory. Nil is unlimited.
	QuotaBytes *uint64
	// StatVirtualization is the guest-visible metadata policy. The zero value
	// is Strict, which needs writable user.* xattrs on the host directory
	// even for a read-only child.
	StatVirtualization StatVirtualization
	// Cache is the guest caching policy. The zero value is Auto.
	Cache MountTableCache
}

// Table returns a MountConfig that serves a mount table at its guest path:
// one read-only directory listing children that are attached, detached and
// switched between read-only and read-write while the sandbox runs, through
// Sandbox.AttachMount, Sandbox.DetachMount and Sandbox.SetMountReadonly.
//
// children are attached at launch. A sandbox has at most one mount table and
// cannot be checkpointed while it has one. Local backend on Linux and macOS
// only.
//
//	microsandbox.WithMounts(map[string]microsandbox.MountConfig{
//	    "/mnt/shared": microsandbox.Mount.Table(microsandbox.MountTableChild{
//	        Name: "data", Host: "/srv/data",
//	    }),
//	})
func (mountFactory) Table(children ...MountTableChild) MountConfig {
	return MountConfig{
		kind:          MountKindTable,
		TableChildren: append([]MountTableChild(nil), children...),
	}
}

// AttachMount attaches a child to the sandbox's mount table under a name that
// is not attached. The guest sees it at its next lookup, without a restart.
// Changes are not written back to the sandbox's configuration: a restart
// attaches only the children it was created with.
func (s *Sandbox) AttachMount(ctx context.Context, child MountTableChild) error {
	return s.updateMounts(ctx, []mountChange{{Change: "attach", Child: buildFFIMountTableChild(child)}})
}

// DetachMount detaches a child from the sandbox's mount table. Files and
// directories the guest still holds inside it fail with ESTALE.
func (s *Sandbox) DetachMount(ctx context.Context, name string) error {
	return s.updateMounts(ctx, []mountChange{{Change: "detach", Name: name}})
}

// SetMountReadonly switches a mount-table child between read-only and
// read-write. Read-only also refuses writes through files the guest opened
// before the switch; such writes fail with EROFS.
func (s *Sandbox) SetMountReadonly(ctx context.Context, name string, readonly bool) error {
	return s.updateMounts(ctx, []mountChange{{Change: "set_mode", Name: name, Readonly: &readonly}})
}

// mountChange is the wire form of one mount-table change.
type mountChange struct {
	Change   string               `json:"change"`
	Child    *ffi.MountTableChild `json:"child,omitempty"`
	Name     string               `json:"name,omitempty"`
	Readonly *bool                `json:"readonly,omitempty"`
}

func (s *Sandbox) updateMounts(ctx context.Context, changes []mountChange) error {
	payload, err := json.Marshal(changes)
	if err != nil {
		return &Error{Kind: ErrInvalidConfig, Message: fmt.Sprintf("encode mount changes: %v", err)}
	}
	return wrapFFI(s.inner.UpdateMounts(ctx, string(payload)))
}

func validateMountTables(mounts map[string]MountConfig) error {
	tables := 0
	for _, mount := range mounts {
		if mount.kind == MountKindTable {
			tables++
		}
	}
	if tables > 1 {
		return &Error{Kind: ErrInvalidConfig, Message: "a sandbox can have at most one mount table"}
	}
	return nil
}

func buildFFIMountTable(guest string, children []MountTableChild) *ffi.MountTableSpec {
	table := &ffi.MountTableSpec{Guest: guest}
	for _, child := range children {
		table.Children = append(table.Children, *buildFFIMountTableChild(child))
	}
	return table
}

func buildFFIMountTableChild(child MountTableChild) *ffi.MountTableChild {
	stat := child.StatVirtualization
	if stat == StatVirtualizationDefault {
		stat = StatVirtualizationStrict
	}
	return &ffi.MountTableChild{
		Name:               child.Name,
		Host:               child.Host,
		Readonly:           child.Readonly,
		QuotaBytes:         child.QuotaBytes,
		StatVirtualization: string(stat),
		Cache:              string(child.Cache),
	}
}
