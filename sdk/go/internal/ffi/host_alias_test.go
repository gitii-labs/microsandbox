package ffi

import (
	"encoding/json"
	"testing"
)

func TestHostAliasIPv4PortsRequireNativeSupport(t *testing.T) {
	for _, supported := range []bool{false, true} {
		if err := validateHostAliasIPv4Ports(nil, supported); err != nil {
			t.Fatal(err)
		}
		if err := validateHostAliasIPv4Ports([]uint16{0}, supported); err == nil {
			t.Fatal("zero port accepted")
		}
		if err := validateHostAliasIPv4Ports([]uint16{1, 65535}, supported); (err == nil) != supported {
			t.Fatalf("supported=%v: %v", supported, err)
		}
	}
}

func TestHostAliasIPv4PortsWireShape(t *testing.T) {
	for _, options := range []any{
		NetworkOptions{HostAliasIPv4Ports: []uint16{12345}},
		RestoreOptions{HostAliasIPv4Ports: []uint16{12345}},
	} {
		encoded, err := json.Marshal(options)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		if string(got["host_alias_ipv4_ports"]) != "[12345]" {
			t.Fatalf("lost ports: %s", encoded)
		}
	}
}
