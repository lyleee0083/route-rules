package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRetiredIntegrationRejectedWithoutWrites(t *testing.T) {
	for _, kind := range []string{"empty-table", "include-section", "include-option", "forward-rule"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			base := f.c.run
			f.c.run = func(input, command string, args ...string) ([]byte, error) {
				key := command + " " + strings.Join(args, " ")
				if kind == "empty-table" && key == "nft -j list tables" {
					return []byte(`{"nftables":[{"table":{"family":"inet","name":"fw4"}},{"table":{"family":"inet","name":"sb_fw4"}}]}`), nil
				}
				if kind == "include-section" && key == "uci -q show firewall" {
					return []byte("firewall.sb_fw4_forward=include\n"), nil
				}
				if kind == "include-option" && key == "uci -q show firewall" {
					return []byte("firewall.sb_fw4_forward.path='/etc/sing-box/forwarding.nft'\n"), nil
				}
				return base(input, command, args...)
			}
			if kind == "forward-rule" {
				f.forward = []any{map[string]any{"comment": "sing-box-fw4-to-tun"}}
			}
			if _, err := f.c.preflight(); err == nil {
				t.Fatal("retired object was accepted")
			}
			if len(f.writes) != 0 {
				t.Fatalf("preflight changed state: %v", f.writes)
			}
		})
	}
}

func TestRetiredNFTTableDetectionChecksFamilyAndShape(t *testing.T) {
	cases := []struct {
		name    string
		payload any
		wantErr bool
	}{
		{
			name:    "retired inet table",
			payload: map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"family": "inet", "name": "sb_fw4"}}}},
			wantErr: true,
		},
		{
			name:    "same name in another family",
			payload: map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"family": "ip", "name": "sb_fw4"}}}},
		},
		{
			name:    "retired name with unknown family",
			payload: map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"name": "sb_fw4"}}}},
			wantErr: true,
		},
		{
			name:    "malformed table listing",
			payload: map[string]any{"nftables": []any{map[string]any{"table": "sb_fw4"}}},
			wantErr: true,
		},
		{
			name: "mixed metainfo and retired table",
			payload: map[string]any{"nftables": []any{map[string]any{
				"metainfo": map[string]any{"version": "test"},
				"table":    map[string]any{"family": "inet", "name": "sb_fw4"},
			}}},
			wantErr: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := rejectLegacyTables(test.payload)
			if (err != nil) != test.wantErr {
				t.Fatalf("rejectLegacyTables() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestRetiredPathRejection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "retired")
	if err := rejectLegacyPaths([]string{path}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyPaths([]string{path}); err == nil {
		t.Fatal("retired directory accepted")
	}
}

func TestBridgeDNSWithoutJournalBlocksStopWithoutMutation(t *testing.T) {
	f := newFixture(t)
	f.dns = bridgeDNS()
	before := bridgeDNS()
	err := f.c.stop()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "dns") {
		t.Fatalf("unreferenced bridge DNS was not reported as a conflict: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("stop changed state without a recovery journal: %v", f.writes)
	}
	if !reflect.DeepEqual(f.dns, before) {
		t.Fatal("stop modified unreferenced bridge DNS")
	}
}

func TestActivationRejectsUnreferencedBridgeDNS(t *testing.T) {
	f := newFixture(t)
	f.dns = bridgeDNS()
	if _, err := f.c.preflight(); err == nil || !strings.Contains(err.Error(), "unreferenced bridge DNS") {
		t.Fatalf("preflight accepted the orphaned bridge: %v", err)
	}
	if err := f.c.prepare(); err == nil || !strings.Contains(err.Error(), "unreferenced bridge DNS") {
		t.Fatalf("prepare accepted the orphaned bridge: %v", err)
	}
	if _, err := f.c.load(); !os.IsNotExist(err) || len(f.writes) != 0 {
		t.Fatalf("orphaned bridge recorded or mutated: journal=%v writes=%v", err, f.writes)
	}
}

func serviceFixture(t *testing.T) *controller {
	t.Helper()
	c := &controller{state: t.TempDir()}
	if err := os.WriteFile(filepath.Join(c.state, "owner"), []byte("sing-box-native-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServiceStateRejectsAbnormalFiles(t *testing.T) {
	for _, name := range []string{"service.lock", "restoration-status", "service-exit", "mosdns.pid", "sing-box.pid", "core.pid"} {
		t.Run(name, func(t *testing.T) {
			c := serviceFixture(t)
			if err := c.validateServiceState(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(c.state, name)
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := c.validateServiceState(); err == nil {
				t.Fatal("directory accepted as runtime file")
			}
		})
	}
}

func TestServiceLockLinkDoesNotTouchTarget(t *testing.T) {
	c := serviceFixture(t)
	target := filepath.Join(t.TempDir(), "unrelated")
	const content = "unrelated data must survive\n"
	if err := os.WriteFile(target, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(c.state, "service.lock")); err != nil {
		t.Skipf("host cannot create symlink: %v", err)
	}
	if err := c.validateServiceState(); err == nil {
		t.Fatal("symlink accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != content {
		t.Fatalf("link target changed: %q %v", data, err)
	}
}

func TestServiceRestorationStatus(t *testing.T) {
	for _, status := range []string{"restored\n", "not-started\n", "failed\n", "restored\nextra\n", ""} {
		c := serviceFixture(t)
		if err := os.WriteFile(filepath.Join(c.state, "restoration-status"), []byte(status), 0600); err != nil {
			t.Fatal(err)
		}
		err := c.restorationStatus()
		valid := status == "restored\n" || status == "not-started\n"
		if (err == nil) != valid {
			t.Fatalf("status %q: %v", status, err)
		}
	}
}
