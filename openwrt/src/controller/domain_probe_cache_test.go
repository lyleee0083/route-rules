package main

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDomainProbeCacheReusesAndInvalidatesByContentDigest(t *testing.T) {
	var cache domainProbeCache
	firstData := []byte("full:one.test\n")
	firstDigest := [2][32]byte{sha256.Sum256(firstData)}
	builds := 0
	build := func(name string) func() (dnsProbeNames, error) {
		return func() (dnsProbeNames, error) {
			builds++
			return dnsProbeNames{direct: name, haveDirect: true, proxy: "codex-probe.invalid"}, nil
		}
	}

	first, err := cache.resolve(firstDigest, build("one.test"))
	if err != nil || first.direct != "one.test" || builds != 1 {
		t.Fatalf("first result=%+v builds=%d err=%v", first, builds, err)
	}
	cached, err := cache.resolve(firstDigest, build("wrong.test"))
	if err != nil || cached.direct != "one.test" || builds != 1 {
		t.Fatalf("cached result=%+v builds=%d err=%v", cached, builds, err)
	}

	secondData := []byte("full:two.test\n")
	second, err := cache.resolve([2][32]byte{sha256.Sum256(secondData)}, build("two.test"))
	if err != nil || second.direct != "two.test" || builds != 2 {
		t.Fatalf("changed result=%+v builds=%d err=%v", second, builds, err)
	}

	badDigest := [2][32]byte{sha256.Sum256([]byte("invalid"))}
	parseErr := errors.New("invalid rule fixture")
	if _, err = cache.resolve(badDigest, func() (dnsProbeNames, error) {
		builds++
		return dnsProbeNames{}, parseErr
	}); !errors.Is(err, parseErr) || cache.valid {
		t.Fatalf("failed parse left cache valid=%t builds=%d err=%v", cache.valid, builds, err)
	}
	if _, err = cache.resolve(firstDigest, build("one.test")); err != nil || builds != 4 {
		t.Fatalf("cache was not rebuilt after a failed content change: builds=%d err=%v", builds, err)
	}
}

func TestDNSProbeNamesDetectContentChangeWithSameFileMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "dns-direct-domains.txt")
	first := []byte("full:one.test\n")
	second := []byte("full:two.test\n")
	if len(first) != len(second) {
		t.Fatal("test content must retain the same size")
	}
	if err := os.WriteFile(path, first, 0600); err != nil {
		t.Fatal(err)
	}
	fixedTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	c := &controller{root: root}
	initial, err := c.dnsProbeNames()
	if err != nil || initial.direct != "one.test" {
		t.Fatalf("initial names=%+v err=%v", initial, err)
	}
	if err = os.WriteFile(path, second, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	changed, err := c.dnsProbeNames()
	if err != nil || changed.direct != "two.test" {
		t.Fatalf("changed names=%+v err=%v", changed, err)
	}

	malformed := []byte("fail:two.test\n")
	if len(malformed) != len(second) {
		t.Fatal("malformed fixture must retain the same size")
	}
	if err = os.WriteFile(path, malformed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	if _, err = c.dnsProbeNames(); err == nil {
		t.Fatal("changed malformed rules reused stale probe names")
	}
	if err = os.WriteFile(path, first, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	recovered, err := c.dnsProbeNames()
	if err != nil || recovered.direct != "one.test" {
		t.Fatalf("recovered names=%+v err=%v", recovered, err)
	}
}

func TestReadinessSelectsProbesOutsideRejectRules(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(directDomainFile, "full:first.example.org\nfull:other.example.org\ndomain:visible.example.org\n")
	rejectPath := filepath.Join(root, rejectDomainFile)
	write(rejectDomainFile, "full:first.example.org\ndomain:invalid\n")
	c := &controller{root: root, processCheck: func(string) error { return nil }}
	initial, err := c.dnsProbeNames()
	if err != nil || initial.direct != "other.example.org" || initial.node != initial.direct || initial.proxy != "codex-probe.example" {
		t.Fatalf("initial names=%+v err=%v", initial, err)
	}

	// Modify only the reject list, preserving its size and timestamp.
	fixedTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	write(rejectDomainFile, "full:other.example.org\ndomain:example\n")
	info, err := os.Stat(rejectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(rejectPath, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	changed, err := c.dnsProbeNames()
	if err != nil || changed.direct != "first.example.org" || changed.proxy != "codex-probe.invalid" {
		t.Fatalf("changed names=%+v err=%v", changed, err)
	}
	write(rejectDomainFile, "full:first.example.org\ndomain:invalid\n")
	if err = os.Chtimes(rejectPath, fixedTime, fixedTime); err != nil {
		t.Fatal(err)
	}
	updated, err := os.Stat(rejectPath)
	if err != nil || updated.Size() != info.Size() {
		t.Fatalf("reject fixtures must have the same size, err=%v", err)
	}
	changed, err = c.dnsProbeNames()
	if err != nil || changed != initial {
		t.Fatalf("metadata-preserving reject change was not applied: names=%+v err=%v", changed, err)
	}

	write(rejectDomainFile, "domain:example.org\nregexp:^codex-probe\\.invalid$\n")
	calls := map[int][]string{}
	c.dnsProbe = func(port int, name, network string) error {
		calls[port] = append(calls[port], network+":"+name)
		return nil
	}
	for _, stage := range []string{"mosdns-direct-node", "proxy-dns"} {
		if ready, err := c.lifecycleReady(stage); err != nil || !ready {
			t.Fatalf("%s ready=%t err=%v", stage, ready, err)
		}
	}
	for _, port := range []int{15353, 15354} {
		got := calls[port]
		if len(got) != 2 || got[0] != "udp:codex-probe.example" || got[1] != "tcp:codex-probe.example" {
			t.Fatalf("port %d did not probe an allowed name over UDP and TCP: %v", port, got)
		}
	}
	write(rejectDomainFile, "regexp:(?=unsupported)\n")
	if _, err = c.dnsProbeNames(); err == nil {
		t.Fatal("malformed reject file reused cached probe names")
	}
	if err = os.Remove(rejectPath); err != nil {
		t.Fatal(err)
	}
	legacy, err := c.dnsProbeNames()
	if err != nil || legacy.direct != "first.example.org" || legacy.proxy != "codex-probe.invalid" {
		t.Fatalf("legacy names=%+v err=%v", legacy, err)
	}
}

func TestReadinessKeepsInjectedCheckerWithoutDomainFiles(t *testing.T) {
	calls := 0
	c := &controller{readyCheck: func(stage string) (bool, error) {
		calls++
		if stage != "proxy-dns" {
			t.Fatalf("unexpected readiness stage %q", stage)
		}
		return true, nil
	}}
	ready, err := c.readiness("proxy-dns")
	if err != nil || !ready || calls != 1 {
		t.Fatalf("ready=%t calls=%d err=%v", ready, calls, err)
	}
}
