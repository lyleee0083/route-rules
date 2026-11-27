package shelltests

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestNativePOSIXSyntax(t *testing.T) {
	for _, pattern := range []string{"*.sh", "*.init"} {
		paths, err := filepath.Glob(filepath.Join("..", "..", "src", "native", pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) == 0 {
			t.Fatal("native sources missing")
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(bytes.NewReader(data), path); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNativeLockAndRetiredObjectGuards(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", "src", "native", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, name := range []string{"sing-box.init", "sing-box-service.sh", "rollback.sh"} {
		text := read(name)
		if strings.Contains(text, "exec 8>") || strings.Contains(text, "exec 8<") {
			t.Fatalf("%s reopened a lock using a shell redirection", name)
		}
	}
	if !strings.Contains(read("sing-box.init"), "/etc/sing-box/sb-controller service-status") {
		t.Fatal("stop callback bypasses checked bounded lock")
	}
	if !strings.Contains(read("sing-box-service.sh"), "exec \"$directory/sb-controller\" service-start") {
		t.Fatal("startup bypasses no-follow lock acquisition")
	}
	rollback := read("rollback.sh")
	guard, stop := strings.Index(rollback, "for file in service.lock"), strings.Index(rollback, "/etc/init.d/sing-box stop")
	if guard < 0 || stop < guard || !strings.Contains(rollback, "flock -n -x 8") || !strings.Contains(rollback, "exec ./sb-controller service-rollback") {
		t.Fatal("rollback must reject abnormal files before stop and acquire the safe lock")
	}
	install := read("install.sh")
	check, create := strings.Index(install, "./sb-controller legacy-check"), strings.Index(install, "mkdir -m 700 /etc/sing-box")
	if check < 0 || create < check || !strings.Contains(install, "/etc/sing-box-fw4") {
		t.Fatal("fresh installation must reject orphaned retired objects before installation")
	}
	coreCheck := strings.Index(install, "./sb-controller verify-cores")
	if coreCheck < 0 || create < coreCheck || strings.Contains(rollback, "/usr/bin/") ||
		strings.Count(install, "/usr/bin/") != 1 || !strings.Contains(install, "/usr/bin/sing-box -D . check") {
		t.Fatal("verify external cores before installation and preserve them during rollback")
	}
	if !strings.Contains(install, "package_dir=$(pwd -P)") ||
		!strings.Contains(install, "done < \"$package_dir/SHA256SUMS\"") ||
		!strings.Contains(install, "sha256sum -c -") ||
		!strings.Contains(install, "cmp -s /etc/sing-box/SHA256SUMS \"$package_dir/SHA256SUMS\"") {
		t.Fatal("failed-install cleanup must use the original manifest and verify each file before removal")
	}
}

func TestConnectionCacheBootGateOrdering(t *testing.T) {
	install := readNative(t, "install.sh")
	manifestCheck := strings.Index(install, `sha256sum -c "$package_dir/SHA256SUMS"`)
	stage := strings.Index(install, `./sb-controller stage-cache-receipt --payload-sha256 "$payload_sha256" --owner sing-box-native-v1 --package-version "$cache_mode"`)
	complete := strings.Index(install, "install_complete=1")
	if manifestCheck < 0 || stage <= manifestCheck || complete <= stage {
		t.Fatal("installer must stage the boot-bound receipt after installed payload verification and immediately before completion")
	}
	if !strings.Contains(install, `payload_sha256=$(sha256sum SHA256SUMS | awk 'NR==1 {print $1}')`) ||
		!strings.Contains(install, `cache_mode=$(cat connection-cache.mode)`) ||
		!strings.Contains(install, "off-v1:7|ctmark-v1:10") {
		t.Fatal("installer must hash the exact installed manifest and accept only exact versioned marker bytes")
	}

	activate := readNative(t, "activate.sh")
	bootCheck, preflight := strings.Index(activate, "./sb-controller cache-boot-check"), strings.Index(activate, "./sb-controller preflight")
	enable, start := strings.Index(activate, "/etc/init.d/sing-box enable"), strings.Index(activate, "/etc/init.d/sing-box start")
	if bootCheck < 0 || preflight <= bootCheck || enable <= preflight || start <= enable {
		t.Fatal("activation must pass the read-only boot gate before preflight, enable and start")
	}
	if strings.Contains(activate, "RECOVERY_ONLY:") || strings.Contains(activate, "case \"$gate_status\"") {
		t.Fatal("manual activation must fail closed on every nonzero boot-gate result, including recovery-only status")
	}

	service := readNative(t, "sing-box-service.sh")
	serviceGate := strings.Index(service, `"$directory/sb-controller" cache-boot-check`)
	startCommand := strings.Index(service, `exec "$directory/sb-controller" service-start`)
	lock := strings.Index(service, "flock -n -x 8")
	supervise := strings.Index(service, `exec "$directory/sb-controller" supervise`)
	if serviceGate < 0 || startCommand <= serviceGate || lock <= serviceGate || supervise <= lock {
		t.Fatal("both unlocked service-start and locked supervise paths must be behind the read-only boot gate")
	}
	if !strings.Contains(service, `case "$gate_status" in`) ||
		!strings.Contains(service, `2)`) ||
		!strings.Contains(service, `RECOVERY_ONLY:\ REBOOT_REQUIRED:*|RECOVERY_ONLY:\ CACHE_GUARD_FAILED:*`) ||
		!strings.Contains(service, `*) printf '%s\n' "$gate_output" >&2; exit "$gate_status";;`) {
		t.Fatal("service wrapper may enter locked prior-boot recovery only for exit 2 and the exact RECOVERY_ONLY reason prefixes")
	}

	rollback := readNative(t, "rollback.sh")
	stop := strings.Index(rollback, "./sb-controller stop")
	proofCleanup := strings.Index(rollback, "./sb-controller cache-rollback-clean")
	checksum := strings.LastIndex(rollback, "sha256sum -c SHA256SUMS")
	stateCheck := strings.Index(rollback, "Recovery or unknown material retained")
	runtimeCheck := strings.Index(rollback, "Unknown runtime file retained")
	if stop < 0 || checksum <= stop || stateCheck <= checksum || runtimeCheck <= stateCheck || proofCleanup <= runtimeCheck {
		t.Fatal("rollback must restore integration and check both inventories before removing boot proof")
	}
}

func TestNativeInitPublicationFollowsStagedModeAndIdentity(t *testing.T) {
	install := readNative(t, "install.sh")
	copyInit := strings.Index(install, `cp sing-box.init "$init_stage"`)
	mode := strings.Index(install, `chmod 755 "$init_stage"`)
	identity := strings.Index(install, `init_identity=$(stat -c '%d:%i' "$init_stage")`)
	publish := strings.Index(install, `./sb-controller publish-install-init`)
	if copyInit < 0 || mode <= copyInit || identity <= mode || publish <= identity ||
		!strings.Contains(install, `= "$init_identity" ]`) || strings.Contains(install, `cp sing-box.init /etc/init.d/sing-box`) {
		t.Fatal("init publication must follow complete private staging, and interrupted cleanup must use file identity")
	}
}

func TestNetworkReadinessRunsInsideSupervisor(t *testing.T) {
	service := readNative(t, "sing-box-service.sh")
	if strings.Contains(service, "ubus call network.interface.wan status") ||
		strings.Contains(service, "jsonfilter") ||
		strings.Contains(service, "SING_BOX_STARTUP_NETWORK_TIMEOUT") {
		t.Fatal("native wrapper performs WAN readiness before the controller can finalize restoration status")
	}
	lock := strings.Index(service, "flock -n -x 8")
	supervise := strings.LastIndex(service, `exec "$directory/sb-controller" supervise`)
	if lock < 0 || supervise <= lock {
		t.Fatal("locked native startup must hand off directly to the Go supervisor")
	}
}

func readNative(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "src", "native", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLinuxServiceLockExecOrderingAndFD8Handoff(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "src", "controller", "service_lock_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	lock := strings.Index(text, "syscall.Flock")
	dup := strings.Index(text, "syscall.Dup3")
	exec := strings.Index(text, "syscall.Exec")
	if lock < 0 || dup <= lock || exec <= dup {
		t.Fatal("Linux service lock must be acquired before fd 8 handoff and exec")
	}
	if strings.Contains(text[lock:exec], "LOCK_UN") || !strings.Contains(text, "syscall.F_SETFD, 0") {
		t.Fatal("Linux service lock must remain held and clear close-on-exec only for fd 8")
	}
}
