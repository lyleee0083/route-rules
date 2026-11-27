package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type fixture struct {
	c                  *controller
	dns                dnsOptions
	include, table     bool
	dormant            bool
	rules              map[string][]any
	routes             map[string][]any
	forward            []any
	nft                any
	foreign            any
	calls, writes      []string
	dnsRestarts        int
	failDNSRestarts    int
	fail               string
	changes, extraDHCP string
	readDNSFails       bool
	boot               string
}

func TestSetDNSRejectsChangedOwnershipBeforeCommit(t *testing.T) {
	for _, option := range []string{"server", "noresolv"} {
		t.Run(option, func(t *testing.T) {
			f := newFixture(t)
			original := f.dns
			if option == "server" {
				f.dns.Servers = []string{"9.9.9.9"}
			} else {
				value := "1"
				f.dns.Noresolv = &value
			}
			changed := f.dns
			err := f.c.setDNS(original, bridgeDNS())
			if err == nil || !strings.Contains(err.Error(), "ownership changed before commit") {
				t.Fatalf("changed DNS ownership not rejected: %v", err)
			}
			if !reflect.DeepEqual(f.dns, changed) || len(f.writes) != 0 || f.dnsRestarts != 0 {
				t.Fatalf("changed DNS settings were mutated: %+v, writes=%v", f.dns, f.writes)
			}
		})
	}
}

func encoded(v any) []byte {
	if items, ok := v.([]any); ok && items == nil {
		v = []any{}
	}
	b, _ := json.Marshal(v)
	return b
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	state := t.TempDir()
	policy, err := os.ReadFile(filepath.Join("..", "native", "policy.template.nft"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(policy)
	for token, value := range map[string]string{"__SB_NETWORKS__": "elements = { 1.1.1.0/24 };", "__SB_DPORTS__": "elements = { 123 };", "__SB_SPORTS__": ""} {
		s = strings.ReplaceAll(s, token, value)
	}
	if err = os.WriteFile(filepath.Join(root, "routing-policy.nft"), []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	original := "0"
	f := &fixture{dns: dnsOptions{Noresolv: &original, Servers: []string{"8.8.8.8", "1.1.1.1"}}, rules: map[string][]any{}, routes: map[string][]any{}, boot: "11111111-1111-1111-1111-111111111111", extraDHCP: "150"}
	f.nft = map[string]any{"nftables": []any{map[string]any{"metainfo": map[string]any{"json_schema_version": 1}}, map[string]any{"table": map[string]any{"family": "inet", "name": "sb_proxy", "handle": 11}}, map[string]any{"set": map[string]any{"family": "inet", "table": "sb_proxy", "name": "direct_net", "type": "ipv4_addr", "elem": []any{"1.1.1.0/24"}, "handle": 12}}}}
	f.foreign = map[string]any{"nftables": []any{}}
	f.c = &controller{root: root, state: state, run: f.run, verify: func() error { return nil }, coreCheck: func() error { return nil }, readyCheck: func(string) (bool, error) { return true, nil }, boot: func() (string, error) { return f.boot, nil }}
	return f
}
func (f *fixture) run(input, command string, args ...string) ([]byte, error) {
	key := command + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if f.fail != "" && strings.Contains(key, f.fail) {
		f.fail = ""
		return nil, errors.New("injected command failure")
	}
	switch command {
	case "fw4":
		if strings.Join(args, " ") != "print" {
			return nil, errors.New("unexpected firewall mutation")
		}
		return []byte("table inet fw4 {}"), nil
	case "nft":
		switch strings.Join(args, " ") {
		case "--version":
			return []byte("nftables fixture"), nil
		case "-j list tables":
			tables := []any{map[string]any{"table": map[string]any{"family": "inet", "name": "fw4"}}}
			if f.table {
				tables = append(tables, map[string]any{"table": map[string]any{"family": "inet", "name": "sb_proxy"}})
			}
			return encoded(map[string]any{"nftables": tables}), nil
		case "-j list ruleset":
			return encoded(f.foreign), nil
		case "list table inet sb_proxy":
			if f.table && f.dormant {
				return []byte("table inet sb_proxy {\n\tflags dormant\n}\n"), nil
			}
			return []byte("table inet sb_proxy {}\n"), nil
		case "-j list table inet sb_proxy":
			if !f.table {
				return nil, errors.New("absent table")
			}
			var snapshot map[string]any
			if err := json.Unmarshal(encoded(f.nft), &snapshot); err != nil {
				return nil, err
			}
			if f.dormant {
				object(object(list(snapshot["nftables"])[1])["table"])["flags"] = []any{"dormant"}
			}
			return encoded(snapshot), nil
		case "-j list chain inet fw4 forward", "-j list chain inet fw4 input":
			entries := []any{}
			for _, r := range f.forward {
				chain := text(object(r)["chain"])
				if chain == "" {
					chain = "forward"
				}
				if args[len(args)-1] != chain {
					continue
				}
				entries = append(entries, map[string]any{"rule": r})
			}
			return encoded(map[string]any{"nftables": entries}), nil
		case "--check -f -":
			if strings.Contains(input, "__SB_") {
				return nil, errors.New("unresolved nft placeholder")
			}
			return nil, nil
		case "-f -":
			f.writes = append(f.writes, key)
			if input == "add table inet sb_proxy\n" {
				if !f.table || !f.dormant {
					return nil, errors.New("cannot enable unstaged table")
				}
				f.dormant = false
				return nil, nil
			}
			if strings.HasPrefix(input, "# Static") {
				if f.table {
					return nil, errors.New("duplicate table")
				}
				f.table = true
				f.dormant = strings.Contains(input, "create table inet sb_proxy {\n    flags dormant;")
				f.forward = []any{map[string]any{"family": "inet", "table": "fw4", "chain": "forward", "comment": "sing-box-to-tun", "handle": 21, "expr": []any{"to-tun"}}, map[string]any{"family": "inet", "table": "fw4", "chain": "forward", "comment": "sing-box-from-tun", "handle": 22, "expr": []any{"from-tun"}}, map[string]any{"family": "inet", "table": "fw4", "chain": "input", "comment": "sing-box-tun-tcp-input", "handle": 23, "expr": []any{"tun-input"}}}
			} else {
				for _, line := range strings.Split(strings.TrimSpace(input), "\n") {
					if line == "delete table inet sb_proxy" {
						f.table = false
						f.dormant = false
						continue
					}
					fields := strings.Fields(line)
					if len(fields) != 7 || strings.Join(fields[:4], " ") != "delete rule inet fw4" || (fields[4] != "forward" && fields[4] != "input") || fields[5] != "handle" {
						return nil, errors.New("unexpected nft deletion: " + line)
					}
					id := fields[6]
					next := []any{}
					for _, entry := range f.forward {
						if text(object(entry)["chain"]) != fields[4] || (text(object(entry)["handle"]) != id && strings.TrimSpace(string(encoded(object(entry)["handle"]))) != id) {
							next = append(next, entry)
						}
					}
					f.forward = next
				}
			}
			return nil, nil
		}
		return nil, errors.New("unexpected nft command: " + key)
	case "ip":
		if strings.Join(args, " ") == "-j link show" {
			return []byte("[]"), nil
		}
		if strings.Join(args, " ") == "-4 -j address show dev br-lan" {
			return []byte(`[{"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.168.50.1","prefixlen":24,"scope":"global"}]}]`), nil
		}
		if strings.Join(args, " ") == "link show dev sb-tun" {
			return []byte("sb-tun"), nil
		}
		if len(args) >= 4 && args[1] == "-j" {
			if args[2] == "rule" {
				return encoded(f.rules[args[0]]), nil
			}
			if args[2] == "route" {
				table := args[len(args)-1]
				if table != "all" {
					items := f.routes[args[0]+"/"+table]
					if len(items) == 0 {
						return []byte("["), errors.New("ip failed: exit status 2: Dump terminated")
					}
					return encoded(items), nil
				}
				keys := []string{}
				for key := range f.routes {
					if strings.HasPrefix(key, args[0]+"/") {
						keys = append(keys, key)
					}
				}
				sort.Strings(keys)
				items := []any{}
				for _, key := range keys {
					for _, entry := range f.routes[key] {
						route := map[string]any{}
						for k, v := range object(entry) {
							route[k] = v
						}
						if _, exists := route["table"]; !exists {
							route["table"] = strings.TrimPrefix(key, args[0]+"/")
						}
						items = append(items, route)
					}
				}
				return encoded(items), nil
			}
		}
		if len(args) >= 3 && (args[2] == "add" || args[2] == "del") {
			f.writes = append(f.writes, key)
			specs := routeSpecs
			if args[1] == "rule" {
				specs = ruleSpecs
			}
			for _, spec := range specs {
				expected := routeArgs(spec, args[2])
				if args[1] == "rule" {
					expected = ruleArgs(spec, args[2])
				}
				if !reflect.DeepEqual(expected, args) {
					continue
				}
				r := map[string]any{}
				items := f.routes
				bucket := spec.family + "/" + spec.table
				if args[1] == "rule" {
					items = f.rules
					bucket = spec.family
					r = map[string]any{"priority": json.Number(spec.priority), "src": "all", "iif": "br-lan", "table": json.Number(spec.table)}
					if spec.table == "main" {
						r["table"] = "main"
					}
					if spec.mark != "" {
						r["fwmark"] = spec.mark
						r["fwmask"] = spec.mark
					}
				} else {
					r = map[string]any{"dst": "default", "protocol": "boot", "scope": "global", "flags": []any{}}
					if spec.device == "" {
						r["type"] = "unreachable"
					} else {
						r["dev"] = spec.device
					}
					if spec.metric != "" {
						r["metric"] = json.Number(spec.metric)
					}
				}
				if args[2] == "add" {
					items[bucket] = append(items[bucket], r)
				} else {
					next := []any{}
					for _, entry := range items[bucket] {
						same := routeMatches(object(entry), spec)
						if args[1] == "rule" {
							same = ruleMatches(object(entry), spec)
						}
						if !same {
							next = append(next, entry)
						}
					}
					items[bucket] = next
				}
				return nil, nil
			}
			return nil, errors.New("unexpected policy mutation: " + key)
		}
		return nil, errors.New("unexpected ip command: " + key)
	case "uci":
		switch strings.Join(args, " ") {
		case "changes dhcp", "changes firewall":
			return []byte(f.changes), nil
		case "-q show dhcp.@dnsmasq[0]":
			if f.readDNSFails {
				return nil, errors.New("UCI read failed")
			}
			s := "dhcp.cfg1=dnsmasq\ndhcp.cfg1.dnsforwardmax='" + f.extraDHCP + "'\n"
			if f.dns.Noresolv != nil {
				s += "dhcp.cfg1.noresolv='" + *f.dns.Noresolv + "'\n"
			}
			if len(f.dns.Servers) != 0 {
				s += "dhcp.cfg1.server='" + strings.Join(f.dns.Servers, "' '") + "'\n"
			}
			return []byte(s), nil
		case "-q show firewall":
			if !f.include {
				return []byte("firewall.cfg=defaults\n"), nil
			}
			return []byte("firewall.sb_proxy_forward=include\nfirewall.sb_proxy_forward.type='nftables'\nfirewall.sb_proxy_forward.path='/etc/sing-box/forwarding.nft'\nfirewall.sb_proxy_forward.position='chain-pre'\nfirewall.sb_proxy_forward.chain='forward'\nfirewall.sb_proxy_input=include\nfirewall.sb_proxy_input.type='nftables'\nfirewall.sb_proxy_input.path='/etc/sing-box/tun-input.nft'\nfirewall.sb_proxy_input.position='chain-pre'\nfirewall.sb_proxy_input.chain='input'\n"), nil
		case "batch":
			f.writes = append(f.writes, key)
			for _, line := range strings.Split(strings.TrimSpace(input), "\n") {
				switch {
				case line == "delete dhcp.@dnsmasq[0].server":
					f.dns.Servers = nil
				case line == "delete dhcp.@dnsmasq[0].noresolv":
					f.dns.Noresolv = nil
				case strings.HasPrefix(line, "set dhcp.@dnsmasq[0].noresolv='"):
					value := strings.TrimSuffix(strings.TrimPrefix(line, "set dhcp.@dnsmasq[0].noresolv='"), "'")
					f.dns.Noresolv = &value
				case strings.HasPrefix(line, "add_list dhcp.@dnsmasq[0].server='"):
					f.dns.Servers = append(f.dns.Servers, strings.TrimSuffix(strings.TrimPrefix(line, "add_list dhcp.@dnsmasq[0].server='"), "'"))
				case strings.HasPrefix(line, "set firewall.sb_proxy_forward"), strings.HasPrefix(line, "set firewall.sb_proxy_input"):
					f.include = true
				case line == "delete firewall.sb_proxy_forward", line == "delete firewall.sb_proxy_input":
					f.include = false
				case line == "commit dhcp", line == "commit firewall":
				default:
					return nil, errors.New("out-of-scope UCI mutation: " + line)
				}
			}
			return nil, nil
		}
		return nil, errors.New("unexpected UCI command: " + key)
	case "/etc/init.d/dnsmasq":
		if strings.Join(args, " ") != "restart" {
			return nil, errors.New("unexpected dnsmasq operation")
		}
		f.dnsRestarts++
		f.writes = append(f.writes, key)
		if f.failDNSRestarts > 0 {
			f.failDNSRestarts--
			return nil, errors.New("injected dnsmasq restart failure")
		}
		return nil, nil
	}
	return nil, errors.New("out-of-scope external command: " + key)
}

func TestUnreferencedObjectsPreventUninstall(t *testing.T) {
	for _, kind := range []string{"table", "forward", "include", "rule"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "table":
				f.table = true
			case "forward":
				f.forward = []any{map[string]any{"comment": "sing-box-unknown"}}
			case "include":
				f.include = true
			case "rule":
				f.rules["-4"] = []any{map[string]any{"priority": json.Number("10075"), "table": json.Number("999")}}
			}
			if err := f.c.stop(); err == nil {
				t.Fatal("unreferenced objects treated as clean uninstall")
			}
			if len(f.writes) != 0 {
				t.Fatal("unreferenced objects changed")
			}
		})
	}
}

func TestLifecycleAndReadOnlyInspection(t *testing.T) {
	f := newFixture(t)
	before := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.dns, before) {
		t.Fatal("prepare changed dnsmasq before the cores were ready")
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.dns, bridgeDNS()) {
		t.Fatal("apply did not attach dnsmasq after core readiness")
	}
	for _, write := range f.writes {
		if strings.HasPrefix(write, "ip -6 ") {
			t.Fatalf("project mutated firmware-owned IPv6 policy: %s", write)
		}
	}
	writes := len(f.writes)
	f.extraDHCP = "777" // Live user resource changes do not invalidate ownership.
	if err := f.c.inspect(); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != writes {
		t.Fatal("inspection mutated state")
	}
	// A firewall reload changes handles, while preserving the included expressions.
	object(f.forward[0])["handle"] = json.Number("801")
	object(f.forward[1])["handle"] = json.Number("802")
	if err := f.c.inspect(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err != nil {
		t.Fatal(err)
	}
	if f.table || f.include || len(f.forward) != 0 || !reflect.DeepEqual(f.dns, before) || f.extraDHCP != "777" {
		t.Fatal("scope restoration failed")
	}
	for _, items := range f.rules {
		if len(items) != 0 {
			t.Fatal("owned rules retained")
		}
	}
	for _, items := range f.routes {
		if len(items) != 0 {
			t.Fatal("owned routes retained")
		}
	}
	j, err := f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("journal=%+v err=%v", j, err)
	}
	if err = f.c.inspect(); err == nil {
		t.Fatal("stopped capture reported active")
	}
}
func TestStartupFaultsRestoreKnownOwnedObjects(t *testing.T) {
	for _, fault := range []string{"ip -4 route add unreachable default metric 42760 table 10073", "uci batch", "ip link show dev sb-tun", "ip -4 route add default dev sb-tun metric 10 table 10074", "nft --check -f -", "nft -f -"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			before := f.dns
			// preflight is read-only, so inject mutations only at their owner stage.
			if strings.HasPrefix(fault, "ip -4 route add unreachable") {
				f.fail = fault
				err := f.c.prepare()
				if err == nil {
					t.Fatal("fault not observed")
				}
			} else {
				if err := f.c.prepare(); err != nil {
					t.Fatal(err)
				}
				f.fail = fault
				if err := f.c.apply(); err == nil {
					t.Fatal("fault not observed")
				}
			}
			if err := f.c.stop(); err != nil {
				t.Fatal(err)
			}
			if f.table || f.include || len(f.forward) != 0 || !reflect.DeepEqual(f.dns, before) {
				t.Fatal("known partial startup not restored")
			}
		})
	}
}

func TestActivationSnapshotsPrecedeRoutingAndDNSChanges(t *testing.T) {
	for _, fault := range []string{"snapshot read failure", "snapshot journal write failure"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			before := f.dns
			if err := f.c.prepare(); err != nil {
				t.Fatal(err)
			}
			fragment := filepath.Join(f.c.state, "journal.json.write")
			base := f.c.run
			f.c.run = func(input, command string, args ...string) ([]byte, error) {
				if command == "nft" && strings.Join(args, " ") == "-j list table inet sb_proxy" {
					if fault == "snapshot read failure" {
						return nil, errors.New(fault)
					}
					if err := os.WriteFile(fragment, []byte("unfinished"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return base(input, command, args...)
			}
			if err := f.c.apply(); err == nil {
				t.Fatal("snapshot failure was ignored")
			}
			if err := f.c.stop(); err == nil || !strings.Contains(err.Error(), "startup hold released") {
				t.Fatalf("cleanup failed to release routing protection and preserve unsigned evidence: %v", err)
			}
			if !f.table || !f.dormant || len(f.forward) != 3 || len(f.rules["-4"]) != 0 ||
				len(f.routes["-4/10073"]) != 0 || len(f.routes["-4/10074"]) != 0 ||
				f.include || !reflect.DeepEqual(f.dns, before) || f.dnsRestarts != 0 {
				t.Fatal("snapshot failure changed native network or removed unverified objects")
			}
		})
	}
}

func TestActivationRecoversAfterEnableCommitsWithError(t *testing.T) {
	f := newFixture(t)
	before := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		result, err := base(input, command, args...)
		if err == nil && command == "nft" && input == "add table inet sb_proxy\n" {
			j, loadErr := f.c.load()
			if loadErr != nil || j.Phase != "dns" || !j.DNSRestartPending || len(j.NFT) == 0 || len(j.Forward) == 0 {
				t.Fatalf("enabled without durable ownership and DNS restart intent: %#v %v", j, loadErr)
			}
			return nil, errors.New("timed out after enabling table")
		}
		return result, err
	}
	if err := f.c.apply(); err == nil || !f.table || f.dormant {
		t.Fatalf("expected an uncertain enable that actually committed: %v", err)
	}
	if err := f.c.stop(); err != nil {
		t.Fatalf("failed to restore durably recorded integration: %v", err)
	}
	if f.table || len(f.forward) != 0 || f.include || len(f.rules["-4"]) != 0 || !reflect.DeepEqual(f.dns, before) {
		t.Fatal("owned integration was not completely restored")
	}
}

func TestActivationRestoresNetworkWhenFinalJournalWriteIsUnavailable(t *testing.T) {
	f := newFixture(t)
	before := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	fragment := filepath.Join(f.c.state, "journal.json.write")
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		result, err := base(input, command, args...)
		if err == nil && command == "nft" && input == "add table inet sb_proxy\n" {
			if err := os.WriteFile(fragment, []byte("unfinished"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return result, err
	}
	if err := f.c.apply(); err == nil || !f.table || f.dormant {
		t.Fatalf("expected active hooks followed by a journal failure: %v", err)
	}
	if err := f.c.stop(); err == nil {
		t.Fatal("final journal write unexpectedly succeeded")
	}
	if f.table || len(f.forward) != 0 || f.include || len(f.rules["-4"]) != 0 || !reflect.DeepEqual(f.dns, before) || f.dnsRestarts != 2 {
		t.Fatal("failed final journal write prevented restoring routing/DNS")
	}
	if data, err := os.ReadFile(fragment); err != nil || string(data) != "unfinished" {
		t.Fatal("existing recovery evidence was not retained")
	}
}

func TestInstallInitPublicationDoesNotClobberDestination(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(t.TempDir(), "sing-box")
	stage := filepath.Join(root, ".install-init")
	if err := os.WriteFile(stage, []byte("prepared init"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := publishInstallInit(root, dest); err == nil {
		t.Fatal("publication accepted a directory at the exact destination")
	}
	if entries, err := os.ReadDir(dest); err != nil || len(entries) != 0 {
		t.Fatalf("publication created a link inside a foreign directory: %v %v", entries, err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := publishInstallInit(root, dest); err != nil {
		t.Fatal(err)
	}
	a, aErr := os.Stat(stage)
	b, bErr := os.Stat(dest)
	if aErr != nil || bErr != nil || !os.SameFile(a, b) {
		t.Fatalf("publication did not link the pre-staged file: %v %v", aErr, bErr)
	}
	if err := publishInstallInit(root, dest); err == nil {
		t.Fatal("publication accepted a second link over an existing file")
	}
}

func TestDNSRestoreRestartFailureIsRetriedBeforeHoldRemoval(t *testing.T) {
	f := newFixture(t)
	original := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	restartsBeforeStop := f.dnsRestarts
	f.failDNSRestarts = 1
	if err := f.c.stop(); err == nil {
		t.Fatal("first DNS restart failure was not reported")
	}
	j, err := f.c.load()
	if err != nil || !j.DNSRestartPending || j.Phase == "restored" {
		t.Fatalf("failed DNS restart lost recovery marker: journal=%+v err=%v", j, err)
	}
	if !reflect.DeepEqual(f.dns, original) {
		t.Fatal("DNS baseline was not written before the injected restart failure")
	}
	held := false
	for _, entry := range f.rules["-4"] {
		if ruleMatches(object(entry), ruleSpecs[0]) {
			held = true
		}
	}
	if !held {
		t.Fatal("restore hold was removed before dnsmasq restarted")
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("retry did not finish DNS restoration: %v", err)
	}
	if f.dnsRestarts != restartsBeforeStop+2 {
		t.Fatalf("retry did not issue a second restart: before=%d after=%d", restartsBeforeStop, f.dnsRestarts)
	}
	j, err = f.c.load()
	if err != nil || j.Phase != "restored" || j.DNSRestartPending {
		t.Fatalf("successful retry did not finalize restoration: journal=%+v err=%v", j, err)
	}
	for _, entry := range f.rules["-4"] {
		if ruleMatches(object(entry), ruleSpecs[0]) {
			t.Fatal("restore hold remained after successful DNS restart")
		}
	}
}
func TestOwnershipConflictsRetainProtection(t *testing.T) {
	for _, change := range []string{"dns", "nft", "forward", "route", "pending-uci", "snapshot-gap"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			if err := f.c.prepare(); err != nil {
				t.Fatal(err)
			}
			if err := f.c.apply(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "dns":
				f.dns.Servers = []string{"9.9.9.9"}
			case "nft":
				object(list(object(f.nft)["nftables"])[2])["foreign"] = true
			case "forward":
				object(f.forward[0])["expr"] = []any{"user-edited"}
			case "route":
				f.routes["-4/10074"] = append(f.routes["-4/10074"], map[string]any{"dst": "10.0.0.0/8", "dev": "user0"})
			case "pending-uci":
				f.changes = "dhcp.user=value"
			case "snapshot-gap":
				j, err := f.c.load()
				if err != nil {
					t.Fatal(err)
				}
				j.NFT = nil
				j.Forward = nil
				if err = f.c.save(j); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.c.stop(); err == nil {
				t.Fatal("ownership conflict silently reset")
			}
			if !f.table || !f.include {
				t.Fatal("conflicting integration removed")
			}
			j, err := f.c.load()
			if err != nil || j.Phase != "active" {
				t.Fatal("recovery evidence lost")
			}
			held := false
			for _, entry := range f.rules["-4"] {
				if ruleMatches(object(entry), ruleSpecs[0]) {
					held = true
				}
			}
			if !held {
				t.Fatal("ownership conflict did not retain the separate startup/restore hold")
			}
		})
	}
}
func TestFreshCollisionsAndReadFailureAreNonMutating(t *testing.T) {
	for _, kind := range []string{"table", "forward", "include", "rule", "route", "mark", "dns-read"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "table":
				f.table = true
			case "forward":
				f.forward = []any{map[string]any{"comment": "sing-box-user"}}
			case "include":
				f.include = true
			case "rule":
				f.rules["-4"] = []any{map[string]any{"priority": json.Number("10075"), "table": json.Number("999")}}
			case "route":
				f.routes["-4/10074"] = []any{map[string]any{"dst": "10.0.0.0/8", "dev": "user0"}}
			case "mark":
				f.foreign = map[string]any{"nftables": []any{map[string]any{"rule": map[string]any{"expr": []any{map[string]any{"mangle": map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": json.Number("1")}}}}}}}
			case "dns-read":
				f.readDNSFails = true
			}
			if err := f.c.prepare(); err == nil {
				t.Fatal("collision accepted")
			}
			if len(f.writes) != 0 {
				t.Fatalf("preflight mutated state: %v", f.writes)
			}
			if _, err := os.Stat(filepath.Join(f.c.state, "journal.json")); !os.IsNotExist(err) {
				t.Fatal("invalid baseline published")
			}
		})
	}
}

func TestMalformedCommandJSONCannotAuthorizeMutation(t *testing.T) {
	for _, name := range []string{"ip -4 -j rule show", "nft -j list tables", "nft -j list ruleset"} {
		for _, bad := range []string{"null", "{}", "[1]", "{\"nftables\":null}", "[] garbage"} {
			t.Run(name+"/"+bad, func(t *testing.T) {
				f := newFixture(t)
				base := f.c.run
				f.c.run = func(input, command string, args ...string) ([]byte, error) {
					if command+" "+strings.Join(args, " ") == name {
						return []byte(bad), nil
					}
					return base(input, command, args...)
				}
				if err := f.c.prepare(); err == nil {
					t.Fatal("malformed command data accepted")
				}
				if len(f.writes) != 0 {
					t.Fatal("malformed data caused mutations")
				}
			})
		}
	}
}
func TestRebootRecoveryAndIncompleteSameBootRefusal(t *testing.T) {
	f := newFixture(t)
	before := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.prepare(); err == nil {
		t.Fatal("same-boot partial lifecycle overwritten")
	}
	// Kernel objects disappear at boot, but the owned UCI baseline persists.
	f.rules = map[string][]any{}
	f.routes = map[string][]any{}
	f.boot = "22222222-2222-2222-2222-222222222222"
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.dns, before) {
		t.Fatal("previous boot baseline lost")
	}
}

func TestRebootRecoveryRemovesValidatedOldBootPIDRecords(t *testing.T) {
	t.Run("owned records removed without signaling", func(t *testing.T) {
		f := newFixture(t)
		baseline := f.dns
		if err := f.c.prepare(); err != nil {
			t.Fatal(err)
		}
		if err := f.c.apply(); err != nil {
			t.Fatal(err)
		}
		// Reboot removes kernel objects only; bridge DNS and the owned UCI include persist.
		f.table = false
		f.forward = nil
		f.rules = map[string][]any{}
		f.routes = map[string][]any{}
		f.boot = "22222222-2222-2222-2222-222222222222"
		for name, pid := range map[string]string{"mosdns.pid": "8123\n", "sing-box.pid": "8124\n"} {
			if err := os.WriteFile(filepath.Join(f.c.state, name), []byte(pid), 0600); err != nil {
				t.Fatal(err)
			}
		}
		recovered, err := f.c.recoverPriorBoot(f.boot)
		if err != nil || !recovered {
			t.Fatalf("old boot recovery blocked on stale owned PID records: recovered=%t err=%v", recovered, err)
		}
		for _, name := range []string{"mosdns.pid", "sing-box.pid"} {
			if _, err := os.Lstat(filepath.Join(f.c.state, name)); !os.IsNotExist(err) {
				t.Fatalf("old boot PID record %s remains: %v", name, err)
			}
		}
		if !reflect.DeepEqual(f.dns, baseline) {
			t.Fatalf("active old-boot DNS baseline was not restored: %#v", f.dns)
		}
		if f.include {
			t.Fatal("active old-boot firewall include was not removed")
		}
		for _, call := range f.calls {
			if strings.Contains(call, "kill") || strings.Contains(call, "signal") {
				t.Fatalf("old boot PID was signaled: %s", call)
			}
		}
		if err = f.c.prepare(); err != nil {
			t.Fatalf("fresh prepare after old boot restoration failed: %v", err)
		}
	})

	for _, test := range []struct {
		name      string
		records   map[string]string
		wantError bool
	}{
		{name: "malformed owned record", records: map[string]string{"mosdns.pid": "8123\n", "sing-box.pid": "not-a-pid\n"}, wantError: true},
		{name: "unknown legacy owner", records: map[string]string{"mosdns.pid": "8123\n", "sing-box.pid": "8124\n", "core.pid": "8125\n"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			if err := f.c.prepare(); err != nil {
				t.Fatal(err)
			}
			f.rules = map[string][]any{}
			f.routes = map[string][]any{}
			f.boot = "22222222-2222-2222-2222-222222222222"
			for name, pid := range test.records {
				if err := os.WriteFile(filepath.Join(f.c.state, name), []byte(pid), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.c.prepare(); (err != nil) != test.wantError {
				t.Fatalf("prepare() error = %v, wantError %t", err, test.wantError)
			}
			for name := range test.records {
				if _, err := os.Lstat(filepath.Join(f.c.state, name)); err != nil {
					t.Fatalf("record %s changed before whole-set validation: %v", name, err)
				}
			}
		})
	}
}

func TestStopDoesNotPersistRestoredBeforeRuntimeCleanupAndCanRetry(t *testing.T) {
	f := newFixture(t)
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(f.c.state, "runtime.nft")
	if err := os.Remove(runtimePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtimePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err == nil {
		t.Fatal("stop succeeded despite unremovable runtime artifact")
	}
	j, err := f.c.load()
	if err != nil {
		t.Fatal(err)
	}
	if j.Phase == "restored" {
		t.Fatal("failed cleanup was persisted as restored")
	}
	if err = f.c.stop(); err == nil {
		t.Fatal("retry reported success while runtime artifact remained")
	}
	if err = os.Remove(runtimePath); err != nil {
		t.Fatal(err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("cleanup retry failed after the blocking artifact was removed: %v", err)
	}
	j, err = f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("successful retry journal phase = %#v, err=%v", j, err)
	}
}

func TestMissingRoutesAndStartupHoldCannotPassInspection(t *testing.T) {
	for _, kind := range []string{"missing-route", "missing-rule", "hold", "core-exited"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if err := f.c.prepare(); err != nil {
				t.Fatal(err)
			}
			if err := f.c.apply(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "core-exited":
				f.c.coreCheck = func() error { return errors.New("core exited") }
			case "missing-route":
				f.routes["-4/10074"] = nil
			case "missing-rule":
				f.rules["-4"] = nil
			case "hold":
				if err := f.c.installRouting(true); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.c.inspect(); err == nil {
				t.Fatal("incomplete capture reported healthy")
			}
		})
	}
}
func TestMarkPreservationProof(t *testing.T) {
	for _, sample := range []struct {
		value string
		safe  bool
	}{
		{`{"|":[{"&":[{"meta":{"key":"mark"}},"0xffffff00"]},"0x11"]}`, true},
		{`{"|":[{"meta":{"key":"mark"}},"0x100"]}`, true},
		{`{"^":[{"meta":{"key":"mark"}},"0x100"]}`, true},
		{`{"&":[{"meta":{"key":"mark"}},"0x9fffffff"]}`, false},
		{`{"|":[{"meta":{"key":"mark"}},"0x20000000"]}`, false},
		{`1`, false}, {`{"ct":{"key":"mark"}}`, false}, {`{"unknown":[]}`, false},
	} {
		value, err := decode([]byte(sample.value))
		if err != nil {
			t.Fatal(err)
		}
		statement := map[string]any{"mangle": map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": value}}
		if (checkMarkWrites(statement) == nil) != sample.safe {
			t.Fatalf("wrong overlap decision: %s", sample.value)
		}
	}
	// Compare symbolic preservation with an independent exhaustive 8-bit oracle
	// for AND/OR/XOR compositions. Unknown upper bits remain conservatively
	// non-identity unless the expression proves preservation.
	ref := map[string]any{"meta": map[string]any{"key": "mark"}}
	for mask := 0; mask < 256; mask++ {
		for value := 0; value < 256; value++ {
			expr := map[string]any{"|": []any{map[string]any{"&": []any{ref, json.Number(strconvInt(mask))}}, json.Number(strconvInt(value))}}
			proof := bits(expr, "meta").identity
			for bit := uint32(1); bit < 256; bit <<= 1 {
				want := mask&int(bit) != 0 && value&int(bit) == 0
				if (proof&bit != 0) != want {
					t.Fatal("bit identity proof diverged")
				}
			}
		}
	}
}
func strconvInt(v int) string { return string(encoded(v)) }
func TestMalformedJournalAndWriteFragmentArePreserved(t *testing.T) {
	for _, name := range []string{"journal.json", "journal.json.write"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			path := filepath.Join(f.c.state, name)
			if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.c.prepare(); err == nil {
				t.Fatal("damaged recovery accepted")
			}
			data, _ := os.ReadFile(path)
			if string(data) != "invalid" || len(f.writes) != 0 {
				t.Fatal("recovery evidence changed")
			}
		})
	}
}

func TestCorePIDRequiresMatchingCommandAndLoadedFile(t *testing.T) {
	for _, kind := range []string{"correct", "missing-mosdns-pid", "bad-mosdns-pid", "wrong-mosdns-command", "old-mosdns-executable", "missing-sing-box-pid", "wrong-sing-box-command", "old-sing-box-executable"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.c.coreCheck = nil
			f.c.procRoot = t.TempDir()
			for _, spec := range []struct {
				name string
				pid  string
				args []string
			}{
				{name: "mosdns", pid: "1234", args: []string{"start", "-c", "mosdns.yaml", "-d", f.c.root}},
				{name: "sing-box", pid: "1235", args: []string{"-D", f.c.root, "run", "-c", filepath.Join(f.c.root, "config.json")}},
			} {
				proc := filepath.Join(f.c.procRoot, spec.pid)
				if err := os.Mkdir(proc, 0700); err != nil {
					t.Fatal(err)
				}
				binary := filepath.Join(f.c.root, spec.name)
				if err := os.WriteFile(binary, []byte(spec.name+" fixture executable"), 0600); err != nil {
					t.Fatal(err)
				}
				missingPID := kind == "missing-"+spec.name+"-pid"
				if !missingPID {
					value := spec.pid + "\n"
					if kind == "bad-mosdns-pid" && spec.name == "mosdns" {
						value = "01234\n"
					}
					if err := os.WriteFile(filepath.Join(f.c.state, spec.name+".pid"), []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args := append([]string{binary}, spec.args...)
				wrongCommand := kind == "wrong-"+spec.name+"-command"
				if wrongCommand {
					args[len(args)-1] = "another-config.yaml"
				}
				if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte(strings.Join(args, "\x00")+"\x00"), 0600); err != nil {
					t.Fatal(err)
				}
				oldExecutable := kind == "old-"+spec.name+"-executable"
				if oldExecutable {
					if err := os.WriteFile(filepath.Join(proc, "exe"), []byte("old executable"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Link(binary, filepath.Join(proc, "exe")); err != nil {
					t.Fatal(err)
				}
			}
			if (f.c.coreRunning() == nil) != (kind == "correct") {
				t.Fatal("stale or unrelated core PID accepted")
			}
		})
	}
}
