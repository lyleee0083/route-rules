package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMixedTCPInputRuleAndLifecycle(t *testing.T) {
	f := newFixture(t)
	policy, err := f.c.renderPolicy()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile(filepath.Join("..", "native", "tun-input.nft"))
	if err != nil {
		t.Fatal(err)
	}
	rule := strings.Split(strings.TrimSpace(string(input)), "\n")[1]
	if !strings.Contains(string(policy), "insert rule inet fw4 input "+rule+"\n") {
		t.Fatal("runtime INPUT rule differs from persistent chain-pre integration")
	}
	if !strings.Contains(rule, `iifname "sb-tun" ip saddr 172.28.255.2 ip daddr 172.28.255.1 meta l4proto tcp ct state { new, established }`) {
		t.Fatal("INPUT exception must be limited to the internal mixed TCP socket pair")
	}
	if !strings.Contains(includeText(), "firewall.sb_proxy_input.chain='input'") || !strings.Contains(includeText(), "/etc/sing-box/tun-input.nft") {
		t.Fatal("INPUT rule will not survive a firewall reload")
	}
	if err = f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err = f.c.apply(); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range f.forward {
		if text(object(entry)["chain"]) == "input" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want one owned input rule, got %d", count)
	}
	if err = f.c.inspect(); err != nil {
		t.Fatal(err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatal(err)
	}
	if f.include || len(f.forward) != 0 {
		t.Fatal("owned INPUT include or rule retained after clean stop")
	}
}

func TestMixedTCPInputCollisionAndTamperRetained(t *testing.T) {
	t.Run("unreferenced-input-rule", func(t *testing.T) {
		f := newFixture(t)
		f.forward = []any{map[string]any{"family": "inet", "table": "fw4", "chain": "input", "comment": "sing-box-tun-tcp-input", "handle": 23}}
		if _, err := f.c.preflight(); err == nil {
			t.Fatal("unreferenced owned INPUT rule accepted")
		}
		if len(f.writes) != 0 {
			t.Fatal("preflight changed collision")
		}
	})
	t.Run("edited-active-input", func(t *testing.T) {
		f := newFixture(t)
		if err := f.c.prepare(); err != nil {
			t.Fatal(err)
		}
		if err := f.c.apply(); err != nil {
			t.Fatal(err)
		}
		object(f.forward[2])["expr"] = []any{"foreign-edit"}
		if err := f.c.inspect(); err == nil {
			t.Fatal("modified INPUT rule accepted")
		}
		if err := f.c.stop(); err == nil {
			t.Fatal("modified INPUT rule deleted during stop")
		}
		if !f.table || len(f.forward) != 3 {
			t.Fatal("conflict did not retain runtime under protection")
		}
	})
}

func TestMixedTCPInputIncludeOwnership(t *testing.T) {
	for _, name := range []string{"missing-input", "wrong-chain", "unknown-option"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.include = true
			run := f.c.run
			f.c.run = func(input, command string, args ...string) ([]byte, error) {
				if command == "uci" && strings.Join(args, " ") == "-q show firewall" {
					data, err := run(input, command, args...)
					if err != nil {
						return nil, err
					}
					s := string(data)
					switch name {
					case "missing-input":
						s = strings.Split(s, "firewall.sb_proxy_input=")[0]
					case "wrong-chain":
						s = strings.ReplaceAll(s, "sb_proxy_input.chain='input'", "sb_proxy_input.chain='forward'")
					case "unknown-option":
						s += "firewall.sb_proxy_input.extra='unknown'\n"
					}
					return []byte(s), nil
				}
				return run(input, command, args...)
			}
			if _, err := f.c.includePresent(); err == nil {
				t.Fatal(errors.New("partial or changed INPUT integration accepted"))
			}
			if len(f.writes) != 0 {
				t.Fatal("ownership read mutated state")
			}
		})
	}
}
