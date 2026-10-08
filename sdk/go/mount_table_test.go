package microsandbox

import (
	"encoding/json"
	"testing"
)

func TestFFIWireShape_MountTable(t *testing.T) {
	quota := uint64(4096)
	got := marshalCreateOptions(t, WithMounts(map[string]MountConfig{
		"/mnt/distributed": Mount.Table(
			MountTableChild{Name: "data", Host: "/srv/data"},
			MountTableChild{
				Name: "secret", Host: "/dev/shm/secret", Readonly: true, QuotaBytes: &quota,
				StatVirtualization: StatVirtualizationOff, HostPermissions: HostPermissionsMirror,
				Cache: MountTableCacheNever,
			},
		),
		"/tmp": Mount.Tmpfs(TmpfsOptions{SizeMiB: 16}),
	}))
	table := mustField(t, got, "mount_table").(map[string]any)
	if table["guest"] != "/mnt/distributed" {
		t.Fatalf("guest = %v", table["guest"])
	}
	children := table["children"].([]any)
	if len(children) != 2 {
		t.Fatalf("children = %v", children)
	}
	data := children[0].(map[string]any)
	// The zero StatVirtualization is sent as the runtime's strict default.
	if data["name"] != "data" || data["host"] != "/srv/data" || data["readonly"] != false ||
		data["stat_virtualization"] != "strict" {
		t.Fatalf("data child = %v", data)
	}
	if _, ok := data["quota_bytes"]; ok {
		t.Fatalf("an unlimited child must omit quota_bytes: %v", data)
	}
	secret := children[1].(map[string]any)
	if secret["readonly"] != true || secret["quota_bytes"] != float64(4096) ||
		secret["stat_virtualization"] != "off" || secret["host_permissions"] != "mirror" ||
		secret["cache"] != "never" {
		t.Fatalf("secret child = %v", secret)
	}
	// The table is not a volume.
	volumes := mustField(t, got, "volumes").(map[string]any)
	if _, ok := volumes["/mnt/distributed"]; ok || len(volumes) != 1 {
		t.Fatalf("volumes = %v", volumes)
	}
}

func TestMountTableChangesWireShape(t *testing.T) {
	readonly := true
	payload, err := json.Marshal([]mountChange{
		{Change: "attach", Child: buildFFIMountTableChild(MountTableChild{Name: "data", Host: "/srv/data"})},
		{Change: "detach", Name: "data"},
		{Change: "set_mode", Name: "data", Readonly: &readonly},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"change":"attach","child":{"name":"data","host":"/srv/data","readonly":false,"stat_virtualization":"strict"}},` +
		`{"change":"detach","name":"data"},{"change":"set_mode","name":"data","readonly":true}]`
	if string(payload) != want {
		t.Fatalf("payload = %s", payload)
	}
}

func TestValidateMountTablesAllowsOne(t *testing.T) {
	one := map[string]MountConfig{"/a": Mount.Table()}
	if err := validateMountTables(one); err != nil {
		t.Fatal(err)
	}
	two := map[string]MountConfig{"/a": Mount.Table(), "/b": Mount.Table()}
	if err := validateMountTables(two); err == nil {
		t.Fatal("two mount tables must be refused")
	}
}
