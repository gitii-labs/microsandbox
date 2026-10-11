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
// host directory or a regular host file.
type MountTableChild struct {
	// Name is the guest-visible name, one path component, unique within the
	// table.
	Name string
	// Host is the absolute host directory or regular file; its type when the
	// child is attached selects the child kind. No path component may be a
	// symlink; resolve a symlinked prefix such as /var on macOS first.
	//
	// A file child follows the path, not the inode: each guest lookup and
	// open resolves Host again, so a file the host replaces by renaming a new
	// one into place shows the new content at the guest's next open. Files the
	// guest already holds open keep the replaced content.
	Host string
	// Readonly refuses every guest mutation, including writes through files
	// the guest opened before the child became read-only.
	Readonly bool
	// QuotaBytes bounds guest writes to the directory or file. Nil is
	// unlimited.
	QuotaBytes *uint64
	// StatVirtualization is the guest-visible metadata policy. The zero value
	// is Strict, which needs writable user.* xattrs on a host directory even
	// for a read-only child, and on a host file that starts read-write.
	StatVirtualization StatVirtualization
	// HostPermissions selects whether guest chmod and create modes reach the
	// host inode. The zero value is Private; Mirror copies ordinary rwx bits.
	HostPermissions HostPermissions
	// Cache is the guest caching policy. The zero value is Auto.
	Cache MountTableCache
	// Owner, when set, is the guest owner presented for entries the runtime's
	// host user owns and that carry no per-file stat override; entries owned
	// by another host user show as 65534. Host inodes are not changed: entries
	// the guest creates are owned by the runtime's host user, and the host
	// kernel checks every access against that user. Requires Strict or Relaxed
	// stat virtualization. Nil shows host owners unchanged.
	Owner *MountOwner
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
	var owner *ffi.MountTableOwner
	if child.Owner != nil {
		owner = &ffi.MountTableOwner{UID: child.Owner.UID, GID: child.Owner.GID}
	}
	return &ffi.MountTableChild{
		Name:               child.Name,
		Host:               child.Host,
		Readonly:           child.Readonly,
		QuotaBytes:         child.QuotaBytes,
		StatVirtualization: string(stat),
		HostPermissions:    string(child.HostPermissions),
		Cache:              string(child.Cache),
		Owner:              owner,
	}
}
