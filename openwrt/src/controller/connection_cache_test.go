package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const cacheTestBootOne = "11111111-1111-1111-1111-111111111111"
const cacheTestBootTwo = "22222222-2222-2222-2222-222222222222"
const cacheTestBootThree = "33333333-3333-3333-3333-333333333333"

func cacheTestPolicyForMode(policy, mode string) string {
	lines := strings.Split(policy, "\n")
	activeLines := func() []string {
		active := make([]string, 0, len(lines))
		for _, raw := range lines {
			active = append(active, strings.TrimSpace(strings.SplitN(raw, "#", 2)[0]))
		}
		return active
	}

	if mode != cacheModeCTMark {
		filtered := make([]string, 0, len(lines))
		for _, raw := range lines {
			line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
			if strings.Contains(line, "__SB_ROUTER_ADDRESSES__") || strings.Contains(line, "ct mark & 0x60000000 ==") || strings.Contains(line, "ct status &") {
				continue
			}
			filtered = append(filtered, raw)
		}
		return strings.Join(filtered, "\n")
	}

	active := activeLines()
	hasDirect, hasProxy := false, false
	for _, line := range active {
		hasDirect = hasDirect || line == cacheDirectFastPathRule
		hasProxy = hasProxy || line == cacheProxyFastPathRule
	}
	if hasDirect || hasProxy {
		return policy
	}
	for i, line := range active {
		if line == "ct direction reply return" {
			inserted := append([]string{}, lines[:i+1]...)
			inserted = append(inserted, cacheDirectFastPathRule, cacheProxyFastPathRule)
			inserted = append(inserted, lines[i+1:]...)
			return strings.Join(inserted, "\n")
		}
	}
	return policy + "\n" + cacheDirectFastPathRule + "\n" + cacheProxyFastPathRule
}

func writeCacheTestPackage(t *testing.T, f *fixture, mode, revision string) string {
	t.Helper()
	policyPath := filepath.Join(f.c.root, "routing-policy.nft")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	policyText := cacheTestPolicyForMode(string(policy), mode)
	if revision != "" {
		policyText += "# package revision: " + revision + "\n"
	}
	if err = atomicWrite(policyPath, []byte(policyText)); err != nil {
		t.Fatal(err)
	}
	marker := []byte(mode + "\n")
	if err = atomicWrite(filepath.Join(f.c.root, cacheModeFile), marker); err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(filepath.Join(f.c.state, "owner"), []byte("sing-box-native-v1\n")); err != nil {
		t.Fatal(err)
	}
	entries := []string{cacheModeFile, "routing-policy.nft"}
	var manifest strings.Builder
	for _, name := range entries {
		data, readErr := os.ReadFile(filepath.Join(f.c.root, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		digest := sha256.Sum256(data)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	manifestBytes := []byte(manifest.String())
	if err = atomicWrite(filepath.Join(f.c.root, "SHA256SUMS"), manifestBytes); err != nil {
		t.Fatal(err)
	}
	f.c.verify = func() error {
		before, listed, verifyErr := f.c.readPackageManifest()
		if verifyErr != nil {
			return verifyErr
		}
		for name, want := range listed {
			data, readErr := readRegularStable(filepath.Join(f.c.root, name), 4*1024*1024)
			if readErr != nil {
				return readErr
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != want {
				return fmt.Errorf("test package digest mismatch for %s", name)
			}
		}
		after, _, verifyErr := f.c.readPackageManifest()
		if verifyErr != nil {
			return verifyErr
		}
		if string(before) != string(after) {
			return errors.New("test package changed during verification")
		}
		return nil
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	return hex.EncodeToString(manifestDigest[:])
}

func stageCacheTestReceipt(t *testing.T, f *fixture, payloadDigest, mode string) {
	t.Helper()
	err := f.c.stageCacheReceipt(payloadDigest, "sing-box-native-v1", mode)
	if err != nil {
		t.Fatal(err)
	}
}

func requireRebootRequired(t *testing.T, err error) {
	t.Helper()
	var reboot rebootRequiredError
	if !errors.As(err, &reboot) {
		t.Fatalf("error=%v, want REBOOT_REQUIRED", err)
	}
}

func cacheLifecycleOnce(t *testing.T, f *fixture) {
	t.Helper()
	f.c.cacheLifecycleAuthorized = true
	decision, err := f.c.checkCacheBoot()
	if err != nil {
		t.Fatal(err)
	}
	f.c.cacheAuthorization = &decision
	if err = f.c.prepare(); err != nil {
		t.Fatalf("prepare (%s): %v", decision.State, err)
	}
	if decision.State == "fresh-boot" {
		if _, exists, readErr := f.c.loadCacheProof(); readErr != nil || exists {
			t.Fatalf("proof was written before apply: exists=%t err=%v", exists, readErr)
		}
	}
	if err = f.c.apply(); err != nil {
		t.Fatalf("apply (%s): %v", decision.State, err)
	}
	receipt, receiptExists, err := f.c.loadCacheReceipt()
	if err != nil || !receiptExists || receipt.ConsumedBootID != f.boot {
		t.Fatalf("successful apply did not consume receipt: exists=%t receipt=%+v err=%v", receiptExists, receipt, err)
	}
	proof, proofExists, err := f.c.loadCacheProof()
	if err != nil || !proofExists || proof.Status != "active" {
		t.Fatalf("successful apply did not commit active proof: exists=%t proof=%+v err=%v", proofExists, proof, err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("stop and restore (%s): %v", decision.State, err)
	}
}

func TestCacheBootGateAndRepeatedSamePackageRestart(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	digest := writeCacheTestPackage(t, f, cacheModeCTMark, "a")
	stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
	journalPath := filepath.Join(f.c.state, "journal.json")
	beforeJournal, readErr := os.ReadFile(journalPath)
	if !os.IsNotExist(readErr) {
		t.Fatalf("unexpected pre-stage journal: %v", readErr)
	}
	callCount := len(f.calls)
	_, err := f.c.checkCacheBoot()
	requireRebootRequired(t, err)
	if len(f.calls) != callCount {
		t.Fatalf("same-boot refusal ran system commands: %v", f.calls[callCount:])
	}
	if after, readErr := os.ReadFile(journalPath); !os.IsNotExist(readErr) || len(beforeJournal) != 0 || len(after) != 0 {
		t.Fatalf("same-boot refusal changed lifecycle journal: bytes=%q err=%v", after, readErr)
	}
	if _, exists, readErr := f.c.loadCacheProof(); readErr != nil || exists {
		t.Fatalf("same-boot refusal created activation proof: exists=%t err=%v", exists, readErr)
	}

	f.boot = cacheTestBootTwo
	decision, err := f.c.checkCacheBoot()
	if err != nil || decision.State != "fresh-boot" {
		t.Fatalf("fresh boot decision=%+v err=%v", decision, err)
	}
	cacheLifecycleOnce(t, f)
	decision, err = f.c.checkCacheBoot()
	if err != nil || decision.State != "same-boot-restart" {
		t.Fatalf("first same-boot restart decision=%+v err=%v", decision, err)
	}
	cacheLifecycleOnce(t, f)
	decision, err = f.c.checkCacheBoot()
	if err != nil || decision.State != "same-boot-restart" {
		t.Fatalf("repeated same-boot restart decision=%+v err=%v", decision, err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("repeated clean stop failed: %v", err)
	}
	decision, err = f.c.checkCacheBoot()
	if err != nil || decision.State != "same-boot-restart" {
		t.Fatalf("repeated stop invalidated genuine proof: decision=%+v err=%v", decision, err)
	}
}

func TestCacheBootGatePrecedesPriorBootRecoveryAndDirectEntryPoints(t *testing.T) {
	t.Run("start-lifecycle", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "staged-now")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		if err := f.c.save(&journal{Version: 1, Boot: f.boot, Phase: "restored", DNS: f.dns}); err != nil {
			t.Fatal(err)
		}
		journalPath := filepath.Join(f.c.state, "journal.json")
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.c.startLifecycle(context.Background())
		requireRebootRequired(t, err)
		after, readErr := os.ReadFile(journalPath)
		if readErr != nil || string(before) != string(after) || len(f.calls) != 0 || len(f.writes) != 0 {
			t.Fatalf("boot refusal ran recovery or changed journal: calls=%v writes=%v err=%v", f.calls, f.writes, readErr)
		}
	})
	t.Run("direct-prepare-apply", func(t *testing.T) {
		f := newFixture(t)
		writeCacheTestPackage(t, f, cacheModeCTMark, "direct-entry")
		if err := f.c.prepare(); err == nil || !strings.Contains(err.Error(), "direct prepare/apply is refused") {
			t.Fatalf("direct prepare was not blocked: %v", err)
		}
		if err := f.c.apply(); err == nil || !strings.Contains(err.Error(), "direct prepare/apply is refused") {
			t.Fatalf("direct apply was not blocked: %v", err)
		}
		if len(f.calls) != 0 || len(f.writes) != 0 {
			t.Fatalf("direct cache entry point mutated network state: calls=%v writes=%v", f.calls, f.writes)
		}
	})
}

func TestCacheGateFailureAllowsOnlyPriorBootRestore(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	digest := writeCacheTestPackage(t, f, cacheModeCTMark, "bad-receipt")
	stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
	if err := atomicWrite(filepath.Join(f.c.state, cacheReceiptFile), []byte("{\"schema_version\":1\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.c.save(&journal{Version: 1, Boot: f.boot, Phase: "active", DNS: f.dns}); err != nil {
		t.Fatal(err)
	}
	f.boot = cacheTestBootTwo
	journalPath := filepath.Join(f.c.state, "journal.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	callCount := len(f.calls)
	err = f.c.cacheBootCheck()
	var recoveryOnly recoveryOnlyError
	if !errors.As(err, &recoveryOnly) || !strings.HasPrefix(err.Error(), "RECOVERY_ONLY: CACHE_GUARD_FAILED:") {
		t.Fatalf("bad receipt with prior-boot journal did not return recovery-only status: %v", err)
	}
	if len(f.calls) != callCount {
		t.Fatalf("read-only recovery status ran system commands: %v", f.calls[callCount:])
	}
	coreCheckCalled := false
	f.c.coreCheck = func() error {
		coreCheckCalled = true
		return errors.New("WAN/core must not be checked")
	}
	_, err = f.c.startLifecycle(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode cache stage receipt") {
		t.Fatalf("prior-boot recovery did not preserve cache gate failure: %v", err)
	}
	if coreCheckCalled {
		t.Fatal("cache gate failure continued into core/network startup")
	}
	after, readErr := os.ReadFile(journalPath)
	if readErr != nil || string(before) == string(after) {
		t.Fatalf("prior-boot journal was not durably restored: err=%v", readErr)
	}
	restored, readErr := f.c.load()
	if readErr != nil || restored.Boot != cacheTestBootOne || restored.Phase != "restored" {
		t.Fatalf("prior-boot journal state=%+v err=%v", restored, readErr)
	}
	if f.table || len(f.forward) != 0 {
		t.Fatalf("recovery-only path installed/retained cache policy: table=%t forward=%v", f.table, f.forward)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "sing-box") || strings.Contains(call, "mosdns") || strings.Contains(call, "fw4 print") {
			t.Fatalf("recovery-only path started new cores or ran preflight: %v", f.calls)
		}
	}
}

func TestCacheNewReceiptAndNewPackageRequireFreshBoot(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	firstDigest := writeCacheTestPackage(t, f, cacheModeCTMark, "a")
	stageCacheTestReceipt(t, f, firstDigest, cacheModeCTMark)
	f.boot = cacheTestBootTwo
	decision, err := f.c.checkCacheBoot()
	if err != nil || decision.State != "fresh-boot" {
		t.Fatalf("package A fresh-boot decision=%+v err=%v", decision, err)
	}
	cacheLifecycleOnce(t, f)
	firstReceipt, exists, err := f.c.loadCacheReceipt()
	if err != nil || !exists {
		t.Fatalf("load first receipt: exists=%t err=%v", exists, err)
	}
	secondDigest := writeCacheTestPackage(t, f, cacheModeCTMark, "b")
	stageCacheTestReceipt(t, f, secondDigest, cacheModeCTMark)
	secondReceipt, exists, err := f.c.loadCacheReceipt()
	if err != nil || !exists || firstReceipt.Nonce == secondReceipt.Nonce || firstReceipt.PayloadSHA256 == secondReceipt.PayloadSHA256 {
		t.Fatalf("new package receipt did not rotate identity: first=%+v second=%+v err=%v", firstReceipt, secondReceipt, err)
	}
	if _, exists, err = f.c.loadCacheProof(); err != nil || exists {
		t.Fatalf("staging new package retained old active proof: exists=%t err=%v", exists, err)
	}
	journalPath := filepath.Join(f.c.state, "journal.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.c.checkCacheBoot()
	requireRebootRequired(t, err)
	after, err := os.ReadFile(journalPath)
	if err != nil || string(before) != string(after) {
		t.Fatalf("same-boot changed-package refusal changed journal: err=%v", err)
	}
	f.boot = cacheTestBootThree
	decision, err = f.c.checkCacheBoot()
	if err != nil || decision.State != "fresh-boot" {
		t.Fatalf("new package did not pass fresh-boot gate with old restored journal: decision=%+v err=%v", decision, err)
	}
	if _, err = f.c.recoverPriorBoot(f.boot); err != nil {
		t.Fatalf("new package could not safely restore previous package lifecycle: %v", err)
	}
	cacheLifecycleOnce(t, f)
}

func TestLegacyJournalRewriteCannotRefreshCacheProof(t *testing.T) {
	t.Run("same-bytes-new-inode", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "legacy-same")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		f.boot = cacheTestBootTwo
		cacheLifecycleOnce(t, f)
		journalPath := filepath.Join(f.c.state, "journal.json")
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		if err = atomicWrite(journalPath, before); err != nil {
			t.Fatal(err)
		}
		_, err = f.c.checkCacheBoot()
		requireRebootRequired(t, err)
		// Simulate a new direct controller stop with no supervised-lifecycle
		// authorization. Cleanup may proceed, but cannot bind the proof again.
		f.c.cacheLifecycleAuthorized = false
		f.c.cacheAuthorization = nil
		if err = f.c.stop(); err != nil {
			t.Fatalf("restored-journal cleanup failed: %v", err)
		}
		_, err = f.c.checkCacheBoot()
		requireRebootRequired(t, err)
	})
	t.Run("changed-journal-content", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "legacy-content")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		f.boot = cacheTestBootTwo
		cacheLifecycleOnce(t, f)
		j, err := f.c.load()
		if err != nil {
			t.Fatal(err)
		}
		changedNoresolv := "1"
		j.DNS.Noresolv = &changedNoresolv
		if err = f.c.save(j); err != nil {
			t.Fatal(err)
		}
		_, err = f.c.checkCacheBoot()
		requireRebootRequired(t, err)
		f.c.cacheLifecycleAuthorized = false
		f.c.cacheAuthorization = nil
		if err = f.c.stop(); err != nil {
			t.Fatalf("changed-journal cleanup failed: %v", err)
		}
		_, err = f.c.checkCacheBoot()
		requireRebootRequired(t, err)
	})
	t.Run("changed-package-payload", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "payload-a")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		f.boot = cacheTestBootTwo
		cacheLifecycleOnce(t, f)
		writeCacheTestPackage(t, f, cacheModeCTMark, "payload-b")
		if _, err := f.c.checkCacheBoot(); err == nil || !strings.Contains(err.Error(), "does not match installed source") {
			t.Fatalf("changed payload was not rejected: %v", err)
		}
		f.c.cacheLifecycleAuthorized = false
		f.c.cacheAuthorization = nil
		if err := f.c.stop(); err != nil {
			t.Fatalf("different-payload journal cleanup failed: %v", err)
		}
		if _, err := f.c.checkCacheBoot(); err == nil || !strings.Contains(err.Error(), "does not match installed source") {
			t.Fatalf("cleanup rebound proof across payload change: %v", err)
		}
	})
}

func TestCacheSourceAndOwnerMismatchFailClosed(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "a")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		writeCacheTestPackage(t, f, cacheModeCTMark, "changed-without-staging")
		f.boot = cacheTestBootTwo
		if _, err := f.c.checkCacheBoot(); err == nil || !strings.Contains(err.Error(), "does not match installed source") {
			t.Fatalf("changed package source accepted: %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.c.state, "journal.json")); !os.IsNotExist(err) {
			t.Fatalf("source mismatch mutated journal: %v", err)
		}
	})
	t.Run("owner", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "a")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		if err := atomicWrite(filepath.Join(f.c.state, "owner"), []byte("foreign-owner\n")); err != nil {
			t.Fatal(err)
		}
		f.boot = cacheTestBootTwo
		if _, err := f.c.checkCacheBoot(); err == nil || !strings.Contains(err.Error(), "unknown integration owner") {
			t.Fatalf("foreign owner accepted: %v", err)
		}
	})
}

func TestCacheReceiptStagingChecksAllSuppliedIdentity(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	digest := writeCacheTestPackage(t, f, cacheModeCTMark, "stage-checks")
	if err := f.c.stageCacheReceipt(strings.Repeat("0", 64), "sing-box-native-v1", cacheModeCTMark); err == nil {
		t.Fatal("incorrect payload digest accepted")
	}
	if err := f.c.stageCacheReceipt(digest, "foreign-owner", cacheModeCTMark); err == nil {
		t.Fatal("incorrect owner accepted")
	}
	if err := f.c.stageCacheReceipt(digest, "sing-box-native-v1", "other-version"); err == nil {
		t.Fatal("incorrect package version accepted")
	}
	if _, exists, err := f.c.loadCacheReceipt(); err != nil || exists {
		t.Fatalf("rejected staging attempt wrote a receipt: exists=%t err=%v", exists, err)
	}
	stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
}

func TestCacheLegacyOffInterpositionInvalidatesProof(t *testing.T) {
	f := newFixture(t)
	writeCacheTestPackage(t, f, cacheModeOff, "off")
	if err := atomicWrite(filepath.Join(f.c.state, cacheProofFile), []byte("stale but structurally invalid")); err != nil {
		t.Fatal(err)
	}
	if err := f.c.invalidateCacheProofForOffMode(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.c.state, cacheProofFile)); !os.IsNotExist(err) {
		t.Fatalf("off mode retained cache proof: %v", err)
	}
	if err := os.Remove(filepath.Join(f.c.root, cacheModeFile)); err != nil {
		t.Fatal(err)
	}
	decision, err := f.c.checkCacheBoot()
	if err != nil || decision.State != "off" || decision.Mode != cacheModeLegacyOff {
		t.Fatalf("legacy package did not retain off behavior: decision=%+v err=%v", decision, err)
	}
}

func TestCachePreparingProofAfterPartialApplyRequiresReboot(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	digest := writeCacheTestPackage(t, f, cacheModeCTMark, "partial")
	stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
	f.boot = cacheTestBootTwo
	f.c.cacheLifecycleAuthorized = true
	decision, err := f.c.checkCacheBoot()
	if err != nil || decision.State != "fresh-boot" {
		t.Fatalf("fresh decision=%+v err=%v", decision, err)
	}
	f.c.cacheAuthorization = &decision
	if err = f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	base := f.c.run
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		if command == "nft" && input == "add table inet sb_proxy\n" {
			return nil, errors.New("injected command failure")
		}
		return base(input, command, args...)
	}
	if err = f.c.apply(); err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("injected policy apply failure not returned: %v", err)
	}
	proof, exists, err := f.c.loadCacheProof()
	if err != nil || !exists || proof.Status != "preparing" {
		t.Fatalf("partial apply did not retain preparing proof: exists=%t proof=%+v err=%v", exists, proof, err)
	}
	if err = f.c.stop(); err != nil {
		t.Fatalf("partial lifecycle restoration failed: %v", err)
	}
	_, err = f.c.checkCacheBoot()
	requireRebootRequired(t, err)
}

func TestCacheReceiptCorruptionAndSymlinkAreRejected(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "corrupt")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		if err := atomicWrite(filepath.Join(f.c.state, cacheReceiptFile), []byte("{}\n")); err != nil {
			t.Fatal(err)
		}
		f.boot = cacheTestBootTwo
		if _, err := f.c.checkCacheBoot(); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("corrupt receipt accepted: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows symlink creation may require Developer Mode or elevation")
		}
		f := newFixture(t)
		f.boot = cacheTestBootOne
		digest := writeCacheTestPackage(t, f, cacheModeCTMark, "symlink")
		stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
		path := filepath.Join(f.c.state, cacheReceiptFile)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.c.state, "owner"), path); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		f.boot = cacheTestBootTwo
		if _, err := f.c.checkCacheBoot(); err == nil {
			t.Fatal("symlink receipt accepted")
		}
	})
}

func TestCacheRollbackCleanRequiresRestorationAndRemovesOnlyReceiptProof(t *testing.T) {
	f := newFixture(t)
	f.boot = cacheTestBootOne
	digest := writeCacheTestPackage(t, f, cacheModeCTMark, "rollback")
	stageCacheTestReceipt(t, f, digest, cacheModeCTMark)
	if err := f.c.save(&journal{Version: 1, Boot: f.boot, Phase: "prepared", DNS: f.dns}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.cacheRollbackClean(); err == nil || !strings.Contains(err.Error(), "restored lifecycle journal") {
		t.Fatalf("cleanup accepted non-restored journal: %v", err)
	}
	if _, exists, err := f.c.loadCacheReceipt(); err != nil || !exists {
		t.Fatalf("refused cleanup removed receipt: exists=%t err=%v", exists, err)
	}
	if err := f.c.save(&journal{Version: 1, Boot: f.boot, Phase: "restored", DNS: f.dns}); err != nil {
		t.Fatal(err)
	}
	unknownPath := filepath.Join(f.c.state, "retained-owner-note")
	if err := os.WriteFile(unknownPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.c.cacheRollbackClean(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{cacheReceiptFile, cacheProofFile} {
		if _, err := os.Stat(filepath.Join(f.c.state, name)); !os.IsNotExist(err) {
			t.Errorf("rollback cleanup retained %s: %v", name, err)
		}
	}
	if data, err := os.ReadFile(unknownPath); err != nil || string(data) != "keep" {
		t.Errorf("rollback cleanup changed an unrelated state file: data=%q err=%v", data, err)
	}
}

func TestCachePolicyModeRequiresExactRouterAddressPlaceholder(t *testing.T) {
	base := strings.Join([]string{
		"table inet sb_proxy {",
		"chain classify {",
		`iifname != "br-lan" return`,
		"meta nfproto != ipv4 return",
		"fib daddr type { local, broadcast, multicast } return",
		"ip daddr @lan_net return",
		"ct direction reply return",
		cacheDirectFastPathRule,
		cacheProxyFastPathRule,
		"}",
		"chain guard {",
		"}",
		"}",
	}, "\n")
	if err := validateCapturePolicyMode(base, cacheModeCTMark); err != nil {
		t.Fatalf("valid confirmed, non-expected cache fast paths rejected: %v", err)
	}
	if err := validateCapturePolicyMode(base+"\n"+cacheDirectFastPathRule, cacheModeCTMark); err == nil {
		t.Fatal("duplicate cache-mode fast path accepted")
	}
	if err := validateCapturePolicyMode(strings.Replace(base, cacheDirectFastPathRule, "", 1), cacheModeCTMark); err == nil {
		t.Fatal("missing direct cache fast path accepted")
	}
	if err := validateCapturePolicyMode(strings.Replace(base, "ct state { new, established }", "ct state { established }", 1), cacheModeCTMark); err == nil {
		t.Fatal("established-only cache fast path accepted")
	}
	if err := validateCapturePolicyMode(strings.Replace(base, "ct status & 0x9 == 0x8", "ct status & 0x1 == 0x1", 1), cacheModeCTMark); err == nil {
		t.Fatal("expected/unconfirmed status predicate accepted")
	}
	if err := validateCapturePolicyMode(strings.Replace(base, cacheDirectFastPathRule+"\n"+cacheProxyFastPathRule, cacheDirectFastPathRule, 1), cacheModeOff); err == nil {
		t.Fatal("cache-off mode accepted a connection-verdict fast path")
	}
	if err := validateCapturePolicyMode("ip saddr 192.0.2.1", cacheModeLegacyOff); err != nil {
		t.Fatalf("legacy off policy rejected: %v", err)
	}
	unsafeOrder := strings.Join([]string{"table inet sb_proxy {", "chain classify {", cacheDirectFastPathRule, cacheProxyFastPathRule, `iifname != "br-lan" return`, "meta nfproto != ipv4 return", "fib daddr type { local, broadcast, multicast } return", "ip daddr @lan_net return", "ct direction reply return", "}", "chain guard {", "}", "}"}, "\n")
	if err := validateCapturePolicyMode(unsafeOrder, cacheModeCTMark); err == nil {
		t.Fatal("cache fast path before scope exclusions accepted")
	}
}

func TestCacheRenderPolicySubstitutesActualRouterAddresses(t *testing.T) {
	f := newFixture(t)
	writeCacheTestPackage(t, f, cacheModeCTMark, "render")
	policy, err := f.c.renderPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(policy), "__SB_ROUTER_ADDRESSES__") || strings.Count(string(policy), "ip saddr != { 192.168.50.1 }") != 2 {
		t.Fatalf("rendered cache policy did not use discovered router address: %s", policy)
	}
}
