package ffi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFsStatNanoseconds(t *testing.T) {
	var stat FsStat
	if err := json.Unmarshal([]byte(`{"modified_unix":1700000000,"modified_nsec":123456789,"inode":1234}`), &stat); err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(1700000000, 123456789); !stat.ModTime().Equal(want) || stat.Inode != 1234 {
		t.Fatalf("stat: %+v, mtime %v; want %v", stat, stat.ModTime(), want)
	}
}

func TestFsStatOldAndMissingTime(t *testing.T) {
	for _, tc := range []struct {
		json string
		want time.Time
	}{
		{`{"modified_unix":1700000000}`, time.Unix(1700000000, 0)},
		{`{"modified_unix":null,"modified_nsec":123456789}`, time.Time{}},
	} {
		var stat FsStat
		if err := json.Unmarshal([]byte(tc.json), &stat); err != nil {
			t.Fatal(err)
		}
		if !stat.ModTime().Equal(tc.want) || stat.Inode != 0 {
			t.Fatalf("%s: %+v; mtime %v, want %v", tc.json, stat, stat.ModTime(), tc.want)
		}
	}
}
