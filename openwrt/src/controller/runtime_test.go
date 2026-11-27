package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMosDNSDomainSetSyntax(t *testing.T) {
	rules, err := parseDNSDomainRules([]byte("\ufeff# generated set\nfull:Exact.Example.\ndomain:Example.NET\nregexp:(^|\\.)direct[0-9]+\\.test\\.?$\nregexp:^UPPER\\.test$\nregexp:^dot\\.test\\.$\nfull:_-\nfull:192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 7 {
		t.Fatalf("parsed %d rules", len(rules))
	}
	checks := []struct {
		index int
		name  string
		match bool
	}{
		{0, "exact.example", true},
		{0, "child.exact.example", false},
		{1, "example.net", true},
		{1, "sub.example.net", true},
		{1, "notexample.net", false},
		{2, "direct42.test", true},
		{2, "sub.direct42.test.", true},
		{2, "DIRECT42.test", true}, // MosDNS normalizes the input, not the regex source.
		{3, "upper.test", false},   // The supplied uppercase regexp itself is not rewritten.
		{4, "dot.test.", false},    // MosDNS strips the terminal dot before regex matching.
		{5, "_-.", true},           // Source normalization accepts underscores, one label, and edge hyphens.
		{6, "192.0.2.1", true},     // Domain-set input is not reclassified as an IP literal.
	}
	for _, check := range checks {
		if got := rules[check.index].matches(check.name); got != check.match {
			t.Errorf("rule %d matches %q = %t, want %t", check.index, check.name, got, check.match)
		}
	}
	if _, have := directProbeName(nil, newDNSRejectMatcher(nil)); have {
		t.Fatal("empty direct domain set unexpectedly produced a direct probe")
	}
	priorityRules, err := parseDNSDomainRules([]byte("regexp:.*\\.example\\.org\nfull:literal.example.org\n"))
	if err != nil {
		t.Fatal(err)
	}
	if probe, _ := directProbeName(priorityRules, newDNSRejectMatcher(nil)); probe != "literal.example.org" {
		t.Fatalf("direct probe should prefer full/domain rules over regexp: %q", probe)
	}
	probe, have := directProbeName(rules[2:3], newDNSRejectMatcher(nil))
	if !have || !rules[2].matches(probe) {
		t.Fatalf("regexp direct rule did not produce a matching DNS probe: %q", probe)
	}
	if _, err = parseDNSDomainRules([]byte("regexp:(?=lookahead)example\\.org\n")); err == nil {
		t.Fatal("non-RE2 regular expression accepted")
	}
	if _, err = parseDNSDomainRules([]byte("exact:example.org\n")); err == nil {
		t.Fatal("non-MosDNS exact matcher alias accepted")
	}
}

func TestMosDNSBindingContractRequiresLoopbackMetricsAndExactDNSListeners(t *testing.T) {
	valid := []byte(`{"plugins":[
		{"type":"udp_server","args":{"listen":"127.0.0.1:15353","entry":"ordinary_sequence"}},
		{"type":"tcp_server","args":{"listen":"127.0.0.1:15353","entry":"ordinary_sequence"}},
		{"type":"udp_server","args":{"listen":"127.0.0.1:15354","entry":"node_sequence"}},
		{"type":"tcp_server","args":{"listen":"127.0.0.1:15354","entry":"node_sequence"}}
	],"api":{"http":"127.0.0.1:15357"}}`)
	if _, err := readMosdnsConfig(valid); err != nil {
		t.Fatalf("valid loopback-only MosDNS bindings rejected: %v", err)
	}
	invalid := []struct {
		name string
		text string
	}{
		{name: "wildcard metrics interface", text: strings.Replace(string(valid), "127.0.0.1:15357", "0.0.0.0:15357", 1)},
		{name: "wrong metrics port", text: strings.Replace(string(valid), "127.0.0.1:15357", "127.0.0.1:15358", 1)},
		{name: "duplicate API section", text: strings.TrimSuffix(string(valid), "}") + `,"api":{"http":"127.0.0.1:15357"}}`},
		{name: "external include", text: strings.TrimSuffix(string(valid), "}") + `,"include":["outside.json"]}`},
		{name: "unknown API option", text: strings.Replace(string(valid), `"http":`, `"pprof":`, 1)},
		{name: "duplicate UDP instead of TCP", text: strings.Replace(string(valid), "tcp_server", "udp_server", 1)},
		{name: "wildcard DNS listener", text: strings.Replace(string(valid), "127.0.0.1:15353", "0.0.0.0:15353", 1)},
		{name: "extra DNS listener", text: strings.Replace(string(valid), "127.0.0.1:15354", "127.0.0.1:15355", 1)},
		{name: "missing API", text: strings.Replace(string(valid), `,"api":{"http":"127.0.0.1:15357"}`, "", 1)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readMosdnsConfig([]byte(test.text)); err == nil {
				t.Fatal("invalid MosDNS binding contract was accepted")
			}
		})
	}
}

func TestEmptyMosDNSDirectSetStillChecksNodeListeners(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.c.root, "dns-direct-domains.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	f.c.processCheck = func(name string) error {
		if name != "mosdns" {
			t.Fatalf("unexpected process identity check %q", name)
		}
		return nil
	}
	var probes []string
	f.c.dnsProbe = func(port int, name, network string) error {
		probes = append(probes, strings.Join([]string{strconv.Itoa(port), name, network}, "/"))
		return nil
	}
	ready, err := f.c.lifecycleReady("mosdns-direct-node")
	if err != nil || !ready {
		t.Fatalf("empty direct set should still permit node readiness: ready=%t err=%v", ready, err)
	}
	if len(probes) != 2 || probes[0] != "15354/codex-probe.invalid/udp" || probes[1] != "15354/codex-probe.invalid/tcp" {
		t.Fatalf("empty direct set did not skip only direct probes: %v", probes)
	}
}

func TestSingBoxPayloadContract(t *testing.T) {
	valid := map[string]any{
		"inbounds": []any{
			map[string]any{"type": "tun", "interface_name": "sb-tun", "address": []any{"172.28.255.1/30"}, "stack": "mixed", "dns_mode": "disabled", "auto_route": false, "auto_redirect": false},
			map[string]any{"type": "socks", "tag": "dns-proxy-in", "listen": "127.0.0.1", "listen_port": 15355},
		},
		"route":     map[string]any{"rules": []any{map[string]any{"ip_version": 6, "action": "reject"}}, "final": "proxy", "default_domain_resolver": map[string]any{"server": "node-dns", "strategy": "ipv4_only", "timeout": "5s"}},
		"outbounds": []any{map[string]any{"type": "selector", "tag": "proxy"}},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "node-dns", "server": "127.0.0.1", "server_port": 15354}}, "final": "node-dns", "strategy": "ipv4_only", "disable_cache": true},
	}
	data, _ := json.Marshal(valid)
	if err := validateSingBoxPayload(data); err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}
	invalid := []func(map[string]any){
		func(config map[string]any) {
			config["inbounds"] = append(list(config["inbounds"]), map[string]any{"type": "direct"})
		},
		func(config map[string]any) { object(list(config["inbounds"])[0])["auto_redirect"] = true },
		func(config map[string]any) { object(list(config["inbounds"])[0])["address"] = []any{"10.0.0.1/30"} },
		func(config map[string]any) { object(list(config["inbounds"])[0])["stack"] = "gvisor" },
		func(config map[string]any) { object(config["route"])["rule_set"] = []any{"proxy"} },
		func(config map[string]any) {
			object(config["route"])["default_domain_resolver"] = map[string]any{"server": "dns-proxy", "strategy": "ipv4_only", "timeout": "5s"}
		},
		func(config map[string]any) {
			object(config["route"])["rules"] = append(list(object(config["route"])["rules"]), map[string]any{"domain_suffix": []any{"example.com"}, "action": "direct"})
		},
	}
	for index, mutate := range invalid {
		cloned, cloneErr := decode(data)
		if cloneErr != nil {
			t.Fatal(cloneErr)
		}
		mutate(object(cloned))
		candidate, _ := json.Marshal(cloned)
		if err := validateSingBoxPayload(candidate); err == nil {
			t.Errorf("invalid contract case %d accepted", index)
		}
	}
}

func TestCapturePolicyRejectsDNSAndIPv6Exceptions(t *testing.T) {
	for _, policy := range []string{
		"chain dns { }",
		"udp dport 53 return",
		"tcp sport 53 accept",
		"redirect to :53",
		"iifname \"br-lan\" meta nfproto ipv6 reject",
		"ip6 daddr ::/0 reject",
		"iifname \"br-lan\" oifname != \"sb-tun\" meta mark & 0x40000000 == 0 reject",
	} {
		if err := validateCapturePolicy(policy); err == nil {
			t.Errorf("forbidden policy accepted: %s", policy)
		}
	}
	if err := validateCapturePolicy("tcp dport { 80, 443 } return\n"); err != nil {
		t.Fatalf("ordinary numeric policy rejected: %v", err)
	}
	if err := validateCapturePolicy("meta nfproto ipv4 reject\n"); err != nil {
		t.Fatalf("explicit IPv4 reject should remain allowed: %v", err)
	}
}

func TestRunLifecycleStopsPeerAndRestoresAfterUnexpectedExit(t *testing.T) {
	type childState struct {
		done    chan struct{}
		once    sync.Once
		stopped int
	}
	children := map[string]*childState{}
	var lock sync.Mutex
	activated := make(chan struct{})
	restored := false
	hooks := lifecycleHooks{
		start: func(name string) (*managedChild, error) {
			state := &childState{done: make(chan struct{})}
			lock.Lock()
			children[name] = state
			lock.Unlock()
			return &managedChild{
				name: name, done: state.done,
				result: func() error { return errors.New("child status 17") },
				stop: func() error {
					lock.Lock()
					state.stopped++
					lock.Unlock()
					state.once.Do(func() { close(state.done) })
					return nil
				},
			}, nil
		},
		ready:          func(string) (bool, error) { return true, nil },
		activate:       func() error { close(activated); return nil },
		restore:        func() error { restored = true; return nil },
		startupTimeout: time.Second,
		retryInterval:  time.Millisecond,
	}
	result := make(chan error, 1)
	go func() { result <- runLifecycle(context.Background(), hooks) }()
	<-activated
	lock.Lock()
	peer := children["sing-box"]
	lock.Unlock()
	if peer == nil {
		t.Fatal("sing-box was not started after mosdns readiness")
	}
	peer.once.Do(func() { close(peer.done) })
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "sing-box exited unexpectedly") {
			t.Fatalf("unexpected exit not reported: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not react to child exit")
	}
	lock.Lock()
	defer lock.Unlock()
	if !restored || children["mosdns"].stopped == 0 || children["sing-box"].stopped == 0 {
		t.Fatal("unexpected exit did not stop both cores and restore owned state")
	}
}

func TestRunLifecycleFailedReadinessStopsStartedCoreAndRestores(t *testing.T) {
	done := make(chan struct{})
	var once sync.Once
	stopped := false
	restored := false
	activated := false
	err := runLifecycle(context.Background(), lifecycleHooks{
		start: func(name string) (*managedChild, error) {
			if name != "mosdns" {
				t.Fatalf("started %s before mosdns became ready", name)
			}
			return &managedChild{
				name: name, done: done, result: func() error { return nil },
				stop: func() error { stopped = true; once.Do(func() { close(done) }); return nil },
			}, nil
		},
		ready: func(stage string) (bool, error) {
			if stage != "mosdns-direct-node" {
				t.Fatalf("unexpected readiness stage %q", stage)
			}
			return false, errors.New("DNS listener not ready")
		},
		activate:       func() error { activated = true; return nil },
		restore:        func() error { restored = true; return nil },
		startupTimeout: 20 * time.Millisecond,
		retryInterval:  time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "readiness timed out") {
		t.Fatalf("readiness failure not reported: %v", err)
	}
	if !stopped || !restored || activated {
		t.Fatal("failed startup did not stop core and restore before capture activation")
	}
}

func TestSupervisorPanicCannotReportRestoredOrSuccessful(t *testing.T) {
	c := &controller{
		root:  t.TempDir(),
		state: t.TempDir(),
		run: func(string, string, ...string) ([]byte, error) {
			panic("injected supervisor panic")
		},
	}
	err := c.supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "service supervisor panic") {
		t.Fatalf("supervisor panic was not returned as an error: %v", err)
	}
	status, readErr := os.ReadFile(filepath.Join(c.state, "restoration-status"))
	if readErr != nil || string(status) != "failed\n" {
		t.Fatalf("panic restoration status = %q, err=%v", status, readErr)
	}
	exit, readErr := os.ReadFile(filepath.Join(c.state, "service-exit"))
	if readErr != nil || string(exit) != "1\n" {
		t.Fatalf("panic service exit = %q, err=%v", exit, readErr)
	}
}

func TestSupervisorPanicCannotTrustOldRestoredPhase(t *testing.T) {
	c := &controller{
		root:  t.TempDir(),
		state: t.TempDir(),
		boot:  func() (string, error) { return "11111111-1111-1111-1111-111111111111", nil },
		run: func(string, string, ...string) ([]byte, error) {
			panic("injected startup panic after prior restoration")
		},
	}
	if err := c.save(&journal{
		Version: 1,
		Boot:    "11111111-1111-1111-1111-111111111111",
		Phase:   "restored",
		DNS:     bridgeDNS(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.state, "runtime.nft"), []byte("retained cleanup artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	err := c.supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "service supervisor panic") {
		t.Fatalf("supervisor panic was not returned: %v", err)
	}
	status, readErr := os.ReadFile(filepath.Join(c.state, "restoration-status"))
	if readErr != nil || string(status) != "failed\n" {
		t.Fatalf("panic with stale restored phase status = %q, err=%v", status, readErr)
	}
}

func TestSupervisorReportsRestoredAfterLifecycleErrorAndSuccessfulCleanup(t *testing.T) {
	f := newFixture(t)
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err != nil {
		t.Fatal(err)
	}
	err := f.c.superviseWith(func() (bool, error) {
		return true, errors.New("sing-box exited unexpectedly")
	})
	if err == nil || !strings.Contains(err.Error(), "exited unexpectedly") {
		t.Fatalf("lifecycle error was lost: %v", err)
	}
	status, err := os.ReadFile(filepath.Join(f.c.state, "restoration-status"))
	if err != nil || string(status) != "restored\n" {
		t.Fatalf("successful cleanup with lifecycle error status = %q, err=%v", status, err)
	}
	exit, err := os.ReadFile(filepath.Join(f.c.state, "service-exit"))
	if err != nil || string(exit) != "1\n" {
		t.Fatalf("lifecycle error exit status = %q, err=%v", exit, err)
	}
}

func TestRestoredPhaseRetainsUnexpectedRuntimeAndSupervisorFails(t *testing.T) {
	f := newFixture(t)
	if err := f.c.save(&journal{
		Version: 1,
		Boot:    f.boot,
		Phase:   "restored",
		DNS:     f.dns,
	}); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(f.c.state, "runtime.nft")
	const retained = "unexpected post-restoration content\n"
	if err := os.WriteFile(runtimePath, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err == nil {
		t.Fatal("restored fast path accepted an unexpected runtime policy")
	}
	data, err := os.ReadFile(runtimePath)
	if err != nil || string(data) != retained {
		t.Fatalf("restored fast path removed or changed runtime policy: %q, err=%v", data, err)
	}
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		if command == filepath.Join(f.c.root, "sing-box") {
			return nil, nil
		}
		return base(input, command, args...)
	}
	if err = f.c.supervise(context.Background()); err == nil || !strings.Contains(err.Error(), "unreferenced runtime policy") {
		t.Fatalf("supervisor did not report the retained runtime policy: %v", err)
	}
	data, err = os.ReadFile(runtimePath)
	if err != nil || string(data) != retained {
		t.Fatalf("supervisor removed or changed runtime policy: %q, err=%v", data, err)
	}
	j, err := f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("review conflict did not preserve restored journal: %#v, err=%v", j, err)
	}
	status, err := os.ReadFile(filepath.Join(f.c.state, "restoration-status"))
	if err != nil || string(status) != "failed\n" {
		t.Fatalf("unexpected runtime policy status = %q, err=%v", status, err)
	}
}

func activeRebootFixture(t *testing.T) (*fixture, dnsOptions) {
	t.Helper()
	f := newFixture(t)
	baseline := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	// Reboot drops kernel objects but leaves the bridge DNS settings and state files.
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
	return f, baseline
}

func TestOldBootRecoveryPrecedesConfigurationCheckFailure(t *testing.T) {
	f, baseline := activeRebootFixture(t)
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		if command == filepath.Join(f.c.root, "sing-box") && strings.Join(args, " ") == "-D "+f.c.root+" check -c "+filepath.Join(f.c.root, "config.json") {
			return nil, errors.New("injected configuration check failure")
		}
		return base(input, command, args...)
	}
	err := f.c.supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "injected configuration check failure") {
		t.Fatalf("configuration-check failure was not returned after recovery: %v", err)
	}
	if !reflect.DeepEqual(f.dns, baseline) {
		t.Fatalf("old boot bridge DNS was not restored before config check: %#v", f.dns)
	}
	for _, name := range []string{"mosdns.pid", "sing-box.pid"} {
		if _, err := os.Lstat(filepath.Join(f.c.state, name)); !os.IsNotExist(err) {
			t.Fatalf("stale old boot PID %s remains after recovery: %v", name, err)
		}
	}
	j, err := f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("recovered old boot journal = %#v, err=%v", j, err)
	}
	status, err := os.ReadFile(filepath.Join(f.c.state, "restoration-status"))
	if err != nil || string(status) != "restored\n" {
		t.Fatalf("configuration failure after successful recovery status = %q, err=%v", status, err)
	}
	exit, err := os.ReadFile(filepath.Join(f.c.state, "service-exit"))
	if err != nil || string(exit) != "1\n" {
		t.Fatalf("configuration failure exit status = %q, err=%v", exit, err)
	}
}

func TestOldBootRecoveryPrecedesBoundedWANTimeout(t *testing.T) {
	f, baseline := activeRebootFixture(t)
	f.c.networkWait = 15 * time.Millisecond
	f.c.networkRetry = time.Millisecond
	base := f.c.run
	configChecked := false
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		if command == filepath.Join(f.c.root, "sing-box") {
			configChecked = true
			return nil, nil
		}
		return base(input, command, args...)
	}
	var stages []string
	f.c.readyCheck = func(stage string) (bool, error) {
		stages = append(stages, stage)
		return false, errors.New("injected WAN down")
	}
	err := f.c.supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WAN network readiness timed out") {
		t.Fatalf("WAN gate did not time out: %v", err)
	}
	if !configChecked || len(stages) == 0 {
		t.Fatalf("startup did not check config then enter the WAN gate: config=%t stages=%v", configChecked, stages)
	}
	for _, stage := range stages {
		if stage != "wan-network" {
			t.Fatalf("unexpected non-network readiness stage before WAN: %q", stage)
		}
	}
	if !reflect.DeepEqual(f.dns, baseline) || f.include {
		t.Fatalf("WAN timeout did not leave old boot integration restored: dns=%#v include=%t", f.dns, f.include)
	}
	for _, name := range []string{"mosdns.pid", "sing-box.pid"} {
		if _, err := os.Lstat(filepath.Join(f.c.state, name)); !os.IsNotExist(err) {
			t.Fatalf("WAN timeout retained stale PID record %s: %v", name, err)
		}
	}
	j, err := f.c.load()
	if err != nil || j.Boot != "11111111-1111-1111-1111-111111111111" || j.Phase != "restored" {
		t.Fatalf("WAN timeout did not preserve old-boot recovery journal: %#v, err=%v", j, err)
	}
	if _, err = os.Lstat(filepath.Join(f.c.state, "runtime.nft")); !os.IsNotExist(err) {
		t.Fatalf("WAN timeout proceeded into fresh prepare: %v", err)
	}
	status, err := os.ReadFile(filepath.Join(f.c.state, "restoration-status"))
	if err != nil || string(status) != "restored\n" {
		t.Fatalf("WAN timeout after successful old-boot restore status = %q, err=%v", status, err)
	}
	exit, err := os.ReadFile(filepath.Join(f.c.state, "service-exit"))
	if err != nil || string(exit) != "1\n" {
		t.Fatalf("WAN timeout exit status = %q, err=%v", exit, err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "kill") || strings.Contains(call, "signal") {
			t.Fatalf("old boot PID was signaled: %s", call)
		}
	}
}

func TestFirstStartupWANTimeoutPublishesNotStartedWithoutIntegrationChanges(t *testing.T) {
	f := newFixture(t)
	f.c.networkWait = 15 * time.Millisecond
	f.c.networkRetry = time.Millisecond
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		if command == filepath.Join(f.c.root, "sing-box") {
			return nil, nil
		}
		return base(input, command, args...)
	}
	f.c.readyCheck = func(stage string) (bool, error) {
		if stage != "wan-network" {
			t.Fatalf("core readiness ran before WAN became ready: %s", stage)
		}
		return false, errors.New("injected first-start WAN down")
	}
	err := f.c.supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WAN network readiness timed out") {
		t.Fatalf("first startup did not return WAN timeout: %v", err)
	}
	for name, expected := range map[string]string{"restoration-status": "not-started\n", "service-exit": "1\n"} {
		data, readErr := os.ReadFile(filepath.Join(f.c.state, name))
		if readErr != nil || string(data) != expected {
			t.Fatalf("%s = %q, err=%v; want %q", name, data, readErr, expected)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("first-start WAN failure changed the integration: %v", f.writes)
	}
	if err = f.c.restorationStatus(); err != nil {
		t.Fatalf("stop status rejects a safely unstarted service: %v", err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("explicit stop cannot proceed after first-start WAN timeout: %v", err)
	}
}

func TestWANReadinessRequiresOwnedInterfaceRouteAndLANAddress(t *testing.T) {
	for _, test := range []struct {
		name      string
		wan       string
		route     string
		lan       string
		wantReady bool
		wantError bool
	}{
		{name: "all ready", wan: `{"up":true,"l3_device":"eth0"}`, route: "default via 192.0.2.1", lan: "br-lan inet 192.168.1.1/24", wantReady: true},
		{name: "wan down", wan: `{"up":false,"l3_device":"eth0"}`},
		{name: "unsafe device", wan: `{"up":true,"l3_device":"eth0;reboot"}`, wantError: true},
		{name: "no default route", wan: `{"up":true,"l3_device":"eth0"}`, lan: "br-lan inet 192.168.1.1/24"},
		{name: "no LAN address", wan: `{"up":true,"l3_device":"eth0"}`, route: "default via 192.0.2.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.c.readyCheck = nil
			f.c.run = func(input, command string, args ...string) ([]byte, error) {
				key := command + " " + strings.Join(args, " ")
				switch key {
				case "ubus call network.interface.wan status":
					return []byte(test.wan), nil
				case "ip link show dev eth0":
					return []byte("2: eth0: <UP>"), nil
				case "ip -4 route show default dev eth0":
					return []byte(test.route), nil
				case "ip -4 -o address show dev br-lan scope global":
					return []byte(test.lan), nil
				default:
					return nil, errors.New("unexpected readiness command: " + key)
				}
			}
			ready, err := f.c.lifecycleReady("wan-network")
			if ready != test.wantReady || (err != nil) != test.wantError {
				t.Fatalf("WAN readiness = %t, err=%v; want ready=%t error=%t", ready, err, test.wantReady, test.wantError)
			}
		})
	}
}
