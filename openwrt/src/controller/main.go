// A finite startup/exit controller. It never polls, reloads the firewall, changes an ECM
// switch, or repairs unrelated user configuration. All commands are injectable
// for offline lifecycle tests; no test needs the host's firewall or network.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const reserved uint32 = 0x60000000
var singBoxHash string
var mosdnsHash string
const includeSection = "firewall.sb_proxy_forward"
const inputIncludeSection = "firewall.sb_proxy_input"

type runner func(input string, command string, args ...string) ([]byte, error)

func execute(input string, command string, args ...string) ([]byte, error) {
	return executeContext(context.Background(), input, command, args...)
}

const commandTimeout = 30 * time.Second
const commandWaitDelay = 500 * time.Millisecond

func executeContext(parent context.Context, input string, command string, args ...string) ([]byte, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s command canceled before start: %w", filepath.Base(command), err)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.WaitDelay = commandWaitDelay
	configureCommandCancellation(cmd)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if contextErr := ctx.Err(); contextErr != nil {
		// A timed-out mutation may already have taken effect. Return failure, never
		// retry here; the caller's journal/ownership checks decide restoration.
		return nil, fmt.Errorf("%s command deadline/cancellation (state may have changed): %w", filepath.Base(command), contextErr)
	}
	if err != nil {
		// Arguments, stdin and command output can contain node credentials.
		return nil, fmt.Errorf("%s failed (state may have changed): %w", filepath.Base(command), err)
	}
	return output, nil
}

type dnsOptions struct {
	Noresolv *string  `json:"noresolv"`
	Servers  []string `json:"servers"`
}
type journal struct {
	Version           int             `json:"version"`
	Boot              string          `json:"boot_id"`
	Phase             string          `json:"phase"`
	DNS               dnsOptions      `json:"original_dns"`
	DNSRestartPending bool            `json:"dns_restart_pending,omitempty"`
	NFT               json.RawMessage `json:"owned_table,omitempty"`
	Forward           json.RawMessage `json:"owned_forward_rules,omitempty"`
}
type controller struct {
	root, state              string
	coreDir                  string
	run                      runner
	domainProbes             domainProbeCache
	boot                     func() (string, error)
	verify                   func() error
	coreCheck                func() error
	readyCheck               func(stage string) (bool, error)
	processCheck             func(name string) error
	dnsProbe                 func(port int, name, network string) error
	networkWait              time.Duration
	networkRetry             time.Duration
	procRoot                 string
	commandContext           context.Context
	cacheLifecycleAuthorized bool
	cacheAuthorization       *cacheGateDecision
	cacheRecoveryOnly        bool
}

func (c *controller) runCommand(input, name string, args ...string) ([]byte, error) {
	if c.commandContext != nil {
		if err := c.commandContext.Err(); err != nil {
			return nil, err
		}
	}
	if c.run != nil { // Offline fixtures retain their injectable runner.
		return c.run(input, name, args...)
	}
	return executeContext(c.commandContext, input, name, args...)
}

// Only synchronous startup checks/activation borrow this context. Restoration
// runs after the scope has unwound, with a fresh per-command deadline.
func (c *controller) withCommandContext(ctx context.Context, action func() error) error {
	previous := c.commandContext
	c.commandContext = ctx
	defer func() { c.commandContext = previous }()
	return action()
}

func (c *controller) readinessContext(ctx context.Context, stage string) (ready bool, err error) {
	err = c.withCommandContext(ctx, func() error {
		ready, err = c.readiness(stage)
		return err
	})
	return ready, err
}

func (c *controller) command(name string, args ...string) ([]byte, error) {
	data, err := c.runCommand("", name, args...)
	if err != nil {
		return nil, err
	}
	jsonQuery := false
	for _, arg := range args {
		if arg == "-j" {
			jsonQuery = true
		}
	}
	if jsonQuery && (name == "ip" || name == "nft") {
		if _, e := decodeCommandObjectList(name, data); e != nil {
			return nil, e
		}
	}
	return data, nil
}

func decodeCommandObjectList(name string, data []byte) ([]any, error) {
	value, err := decode(data)
	if err != nil {
		return nil, err
	}
	var entries []any
	var ok bool
	if name == "ip" {
		entries, ok = value.([]any)
	} else {
		entries, ok = object(value)["nftables"].([]any)
	}
	if !ok {
		return nil, errors.New("command JSON has an unexpected object-list shape")
	}
	for _, entry := range entries {
		if object(entry) == nil {
			return nil, errors.New("invalid command JSON object entry")
		}
	}
	return entries, nil
}
func (c *controller) mutation(name string, args ...string) error {
	_, err := c.command(name, args...)
	return err
}
func (c *controller) batch(name, text string, args ...string) error {
	_, err := c.runCommand(text, name, args...)
	return err
}

func regular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular owned file: %s", path)
	}
	return nil
}
func directory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe directory: %s", path)
	}
	return nil
}
func atomicWrite(path string, data []byte) error {
	if err := directory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = regular(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path+".write", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("retained write fragment requires review: %w", err)
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(path+".write", path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (c *controller) save(j *journal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(c.state, "journal.json"), append(data, '\n'))
}
func (c *controller) load() (*journal, error) {
	path := filepath.Join(c.state, "journal.json")
	if err := regular(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeJournalData(data)
}

func decodeJournalData(data []byte) (*journal, error) {
	var j journal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&j); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing journal data")
	}
	if j.Version != 1 || j.Boot == "" || !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(j.Boot) {
		return nil, errors.New("invalid recovery journal")
	}
	switch j.Phase {
	case "prepared", "nft-staging", "dns", "installed", "active", "restored":
	default:
		return nil, errors.New("unknown journal phase")
	}
	if err := validateDNS(j.DNS); err != nil {
		return nil, err
	}
	for _, raw := range []*json.RawMessage{&j.NFT, &j.Forward} {
		if len(*raw) != 0 {
			value, e := decode(*raw)
			if e != nil {
				return nil, e
			}
			normalized, e := canonical(value)
			if e != nil {
				return nil, e
			}
			*raw = normalized
		}
	}
	return &j, nil
}

func (c *controller) verified() error {
	if c.verify != nil {
		return c.verify()
	}
	if err := c.verifyExternalCores(); err != nil {
		return err
	}
	return c.verifyPayload()
}

func (c *controller) coreRunning() error {
	if c.coreCheck != nil {
		return c.coreCheck()
	}
	if err := c.processRunning("mosdns", c.corePath("mosdns"), []string{"start", "-c", "mosdns.json", "-d", c.root}); err != nil {
		return fmt.Errorf("mosdns process identity: %w", err)
	}
	return c.processRunning("sing-box", c.corePath("sing-box"), []string{"-D", c.root, "run", "-c", filepath.Join(c.root, "config.json")})
}

func (c *controller) processRunning(name, binary string, args []string) error {
	path := filepath.Join(c.state, name+".pid")
	if err := regular(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	value := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(value)
	if err != nil || pid < 2 || strconv.Itoa(pid) != value {
		return fmt.Errorf("invalid current %s PID record", name)
	}
	procRoot := c.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err = os.ReadFile(filepath.Join(procRoot, value, "cmdline"))
	if err != nil {
		return err
	}
	processArgs := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	expected := append([]string{binary}, args...)
	if !reflect.DeepEqual(processArgs, expected) {
		return fmt.Errorf("%s PID belongs to another command/configuration", name)
	}
	loaded, err := os.Stat(filepath.Join(procRoot, value, "exe"))
	if err != nil {
		return err
	}
	installed, err := os.Stat(binary)
	if err != nil {
		return err
	}
	if !os.SameFile(loaded, installed) {
		return fmt.Errorf("%s process has not loaded the installed executable", name)
	}
	return nil
}

const payloadHashBufferSize = 128 * 1024

func boundedHashBuffer(buffer []byte) []byte {
	if len(buffer) == 0 {
		return make([]byte, payloadHashBufferSize)
	}
	if len(buffer) > payloadHashBufferSize {
		return buffer[:payloadHashBufferSize]
	}
	return buffer
}

func streamSHA256(reader io.Reader, buffer []byte) ([32]byte, error) {
	var digest [32]byte
	hasher := sha256.New()
	// Hide WriterTo so the caller's bounded buffer is used even for *os.File.
	_, err := io.CopyBuffer(hasher, struct{ io.Reader }{reader}, boundedHashBuffer(buffer))
	if err != nil {
		return digest, err
	}
	copy(digest[:], hasher.Sum(digest[:0]))
	return digest, nil
}

func digestReadCloser(reader io.ReadCloser, buffer []byte, afterRead func() error) (digest [32]byte, resultErr error) {
	if reader == nil {
		return digest, errors.New("nil payload reader")
	}
	digest, readErr := streamSHA256(reader, buffer)
	var checkErr error
	if afterRead != nil {
		checkErr = afterRead()
	}
	closeErr := reader.Close()
	if readErr != nil {
		if checkErr != nil || closeErr != nil {
			return [32]byte{}, fmt.Errorf("payload digest read failed: %w (file check: %v; close: %v)", readErr, checkErr, closeErr)
		}
		return [32]byte{}, readErr
	}
	if checkErr != nil {
		if closeErr != nil {
			return [32]byte{}, fmt.Errorf("%w (close: %v)", checkErr, closeErr)
		}
		return [32]byte{}, checkErr
	}
	if closeErr != nil {
		return [32]byte{}, fmt.Errorf("close payload after digest: %w", closeErr)
	}
	return digest, nil
}

func openRegularFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("not a regular owned file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, nil, statErr
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("payload path changed while opening: %s", path)
	}
	return file, opened, nil
}

func verifyOpenedRegularFile(path string, file *os.File, opened os.FileInfo) error {
	current, err := file.Stat()
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Size() != current.Size() || !opened.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("payload changed while reading: %s", path)
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !linked.Mode().IsRegular() || !os.SameFile(opened, linked) {
		return fmt.Errorf("payload path changed while reading: %s", path)
	}
	return nil
}

func hashRegularFile(path string, buffer []byte) ([32]byte, error) {
	file, opened, err := openRegularFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return digestReadCloser(file, buffer, func() error {
		return verifyOpenedRegularFile(path, file, opened)
	})
}

func (c *controller) corePath(name string) string {
	dir := c.coreDir
	if dir == "" {
		dir = "/usr/bin"
	}
	return filepath.Join(dir, name)
}

func (c *controller) verifyExternalCores() error {
	buffer := make([]byte, payloadHashBufferSize)
	for _, core := range []struct{ name, sha string }{{"sing-box", singBoxHash}, {"mosdns", mosdnsHash}} {
		path := c.corePath(core.name)
		digest, err := hashRegularFile(path, buffer)
		if err != nil {
			return fmt.Errorf("check external core %s: %w", path, err)
		}
		if hex.EncodeToString(digest[:]) != core.sha {
			return fmt.Errorf("external core %s does not match the pinned project Release", path)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0100 == 0 {
			return fmt.Errorf("external core %s must be executable", path)
		}
	}
	return nil
}

func (c *controller) verifyPayload() error {
	if err := directory(c.root); err != nil {
		return err
	}
	path := filepath.Join(c.root, "SHA256SUMS")
	if err := regular(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	found := map[string]bool{}
	hashBuffer := make([]byte, payloadHashBufferSize)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(parts[0]) || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(parts[1]) || parts[1] == "SHA256SUMS" || parts[1] == "sing-box" || parts[1] == "mosdns" || found[parts[1]] {
			return errors.New("invalid payload manifest")
		}
		found[parts[1]] = true
		path = filepath.Join(c.root, parts[1])
		digest, e := hashRegularFile(path, hashBuffer)
		if e != nil {
			return e
		}
		if hex.EncodeToString(digest[:]) != parts[0] {
			return fmt.Errorf("payload changed: %s", parts[1])
		}
	}
	for _, name := range []string{"config.json", "mosdns.json", "dns-direct-domains.txt", "dns-direct-domains.mdrs", "routing-policy.nft", "forwarding.nft", "tun-input.nft", "sb-controller", "sing-box-service.sh", "sing-box.init"} {
		if !found[name] {
			return fmt.Errorf("required payload missing: %s", name)
		}
	}
	if found["dns-reject-domains.txt"] != found["dns-reject-domains.mdrs"] {
		return errors.New("DNS reject policy requires both its probe rules and compiled rules")
	}
	for _, name := range []string{"dns-reject-domains.txt", "dns-reject-domains.mdrs"} {
		if _, err := os.Lstat(filepath.Join(c.root, name)); err == nil && !found[name] {
			return fmt.Errorf("DNS reject rules are not covered by SHA256SUMS: %s", name)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	modePath := filepath.Join(c.root, cacheModeFile)
	if _, modeErr := os.Lstat(modePath); modeErr == nil {
		if !found[cacheModeFile] {
			return errors.New("cache mode marker is not covered by SHA256SUMS")
		}
		modeBytes, readErr := readRegularStable(modePath, 128)
		if readErr != nil {
			return readErr
		}
		if string(modeBytes) != cacheModeOff+"\n" && string(modeBytes) != cacheModeCTMark+"\n" {
			return errors.New("cache mode marker is malformed or unsupported")
		}
	} else if !os.IsNotExist(modeErr) {
		return modeErr
	}
	data, err = os.ReadFile(filepath.Join(c.root, "config.json"))
	if err != nil {
		return err
	}
	if err = validateSingBoxPayload(data); err != nil {
		return err
	}
	if err = c.validateMosdnsPayload(); err != nil {
		return err
	}
	policy, err := os.ReadFile(filepath.Join(c.root, "routing-policy.nft"))
	if err != nil {
		return err
	}
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return err
	}
	if err = validateCapturePolicyMode(string(policy), mode); err != nil {
		return err
	}
	return nil
}

func decode(data []byte) (any, error) {
	var value any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("null command JSON cannot prove an empty owned object list")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing command JSON")
	}
	return value, nil
}
func object(v any) map[string]any { value, _ := v.(map[string]any); return value }
func list(v any) []any            { value, _ := v.([]any); return value }
func text(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case json.Number:
		return string(value)
	}
	return ""
}
func number(v any) (uint32, bool) {
	s := text(v)
	if s == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 0
	}
	n, err := strconv.ParseUint(s, base, 32)
	return uint32(n), err == nil
}

type bitValue struct{ identity, zero, one uint32 }

func reference(v any) string {
	m := object(v)
	for _, kind := range []string{"meta", "ct"} {
		if text(object(m[kind])["key"]) == "mark" {
			return kind
		}
	}
	return ""
}
func bits(v any, target string) bitValue {
	if reference(v) == target && target != "" {
		return bitValue{identity: ^uint32(0)}
	}
	if n, ok := number(v); ok {
		return bitValue{zero: ^n, one: n}
	}
	m := object(v)
	for _, op := range []string{"&", "|", "^"} {
		operands := list(m[op])
		if len(operands) != 2 {
			continue
		}
		a, b := bits(operands[0], target), bits(operands[1], target)
		switch op {
		case "&":
			return bitValue{identity: (a.identity & b.identity) | (a.identity & b.one) | (b.identity & a.one), zero: a.zero | b.zero, one: a.one & b.one}
		case "|":
			return bitValue{identity: (a.identity & b.identity) | (a.identity & b.zero) | (b.identity & a.zero), zero: a.zero & b.zero, one: a.one | b.one}
		case "^":
			return bitValue{identity: (a.identity & b.zero) | (b.identity & a.zero), zero: (a.zero & b.zero) | (a.one & b.one), one: (a.one & b.zero) | (b.one & a.zero)}
		}
	}
	return bitValue{}
}
func checkMarkWrites(v any) error {
	switch value := v.(type) {
	case map[string]any:
		if m := object(value["mangle"]); m != nil {
			if target := reference(m["key"]); target != "" && bits(m["value"], target).identity&reserved != reserved {
				return errors.New("foreign mark write overlaps reserved 0x60000000 bits; review required")
			}
		}
		for _, child := range value {
			if err := checkMarkWrites(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := checkMarkWrites(child); err != nil {
				return err
			}
		}
	}
	return nil
}
func canonical(v any) ([]byte, error) {
	switch value := v.(type) {
	case map[string]any:
		delete(value, "handle")
		delete(value, "index")
		for key, child := range value {
			if key == "metainfo" {
				delete(value, key)
				continue
			}
			if _, err := canonical(child); err != nil {
				return nil, err
			}
		}
	case []any:
		for _, child := range value {
			if _, err := canonical(child); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(v)
}
func (c *controller) tablePresent() (bool, error) {
	data, err := c.command("nft", "-j", "list", "tables")
	if err != nil {
		return false, err
	}
	value, err := decode(data)
	if err != nil {
		return false, err
	}
	for _, entry := range list(object(value)["nftables"]) {
		t := object(object(entry)["table"])
		if text(t["family"]) == "inet" && text(t["name"]) == "sb_proxy" {
			return true, nil
		}
	}
	return false, nil
}

// Retired names are rejection sentinels, never migration or cleanup targets.
func rejectLegacyPaths(paths []string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("retired integration requires explicit review: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func rejectLegacyTables(value any) error {
	entries, ok := object(value)["nftables"].([]any)
	if !ok {
		return errors.New("nft table listing has an unexpected object-list shape")
	}
	for _, entry := range entries {
		item := object(entry)
		if item["metainfo"] != nil {
			if len(item) != 1 {
				return errors.New("nft table listing contains a mixed metainfo object")
			}
			continue
		}
		table, ok := object(item["table"])["name"].(string)
		if !ok {
			return errors.New("nft table listing contains an invalid table object")
		}
		if table != "sb_fw4" {
			continue
		}
		family, ok := object(item["table"])["family"].(string)
		if !ok || family == "" {
			return errors.New("retired nft table family is unknown; explicit review required")
		}
		if family == "inet" {
			return errors.New("retired nft table requires explicit review")
		}
	}
	return nil
}

func (c *controller) rejectLegacyIntegration() error {
	if err := rejectLegacyPaths([]string{"/etc/sing-box-fw3", "/etc/sing-box-fw4", "/etc/init.d/sb-fw3", "/etc/hotplug.d/iface/99-sb-fw3"}); err != nil {
		return err
	}
	data, err := c.command("nft", "-j", "list", "tables")
	if err != nil {
		return err
	}
	value, err := decode(data)
	if err != nil {
		return err
	}
	if err = rejectLegacyTables(value); err != nil {
		return err
	}
	data, err = c.command("uci", "-q", "show", "firewall")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key := strings.SplitN(line, "=", 2)[0]
		if key == "firewall.sb_fw4_forward" || strings.HasPrefix(key, "firewall.sb_fw4_forward.") {
			return errors.New("retired firewall include requires explicit review")
		}
	}
	return nil
}
func (c *controller) tableSnapshot() ([]byte, error) {
	return c.captureTableSnapshot(false)
}

func (c *controller) captureTableSnapshot(ignoreDormant bool) ([]byte, error) {
	data, err := c.command("nft", "-j", "list", "table", "inet", "sb_proxy")
	if err != nil {
		return nil, err
	}
	value, err := decode(data)
	if err != nil {
		return nil, err
	}
	entries := []any{}
	for _, entry := range list(object(value)["nftables"]) {
		item := object(entry)
		if item["metainfo"] != nil {
			continue
		}
		if table := object(item["table"]); ignoreDormant && text(table["name"]) == "sb_proxy" && text(table["family"]) == "inet" {
			flags := list(table["flags"])
			if text(table["flags"]) == "dormant" || (len(flags) == 1 && text(flags[0]) == "dormant") {
				delete(table, "flags")
			}
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, errors.New("empty owned table snapshot")
	}
	return canonical(entries)
}

func (c *controller) requireCaptureTableState(wantDormant bool) error {
	// Some nft versions omit table flags from JSON. Check the listing itself.
	data, err := c.command("nft", "list", "table", "inet", "sb_proxy")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "table inet sb_proxy {") {
		return errors.New("invalid capture table listing")
	}
	dormant := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSuffix(strings.TrimSpace(line), ";") == "flags dormant" {
			dormant = true
			break
		}
	}
	if dormant != wantDormant {
		return fmt.Errorf("capture table dormant=%t, want %t; review required", dormant, wantDormant)
	}
	return nil
}

// Snapshot only project-commented rules from both system chains. The mixed TCP
// stack reinjects a private 172.28.255.2 -> 172.28.255.1 connection into INPUT;
// forwarding exceptions alone cannot permit that internal socket handshake.
func (c *controller) forwardRules() ([]any, error) {
	found := []any{}
	for _, chain := range []string{"forward", "input"} {
		data, err := c.command("nft", "-j", "list", "chain", "inet", "fw4", chain)
		if err != nil {
			return nil, err
		}
		value, err := decode(data)
		if err != nil {
			return nil, err
		}
		for _, entry := range list(object(value)["nftables"]) {
			rule := object(object(entry)["rule"])
			if strings.HasPrefix(text(rule["comment"]), "sing-box-") {
				found = append(found, rule)
			}
		}
	}
	return found, nil
}
func forwardSnapshot(rules []any) ([]byte, error) {
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	value, err := decode(data)
	if err != nil {
		return nil, err
	}
	return canonical(value)
}

type routeSpec struct {
	family, priority, table, mark, metric, device string
	hold                                          bool
}

var ruleSpecs = []routeSpec{
	{family: "-4", priority: "10073", table: "10073", hold: true},
	{family: "-4", priority: "10074", table: "main", mark: "0x40000000"},
	{family: "-4", priority: "10075", table: "10074"},
}
var routeSpecs = []routeSpec{
	{family: "-4", table: "10073", metric: "42760", hold: true},
	{family: "-4", table: "10074", metric: "42760"},
	{family: "-4", table: "10074", metric: "10", device: "sb-tun"},
}

func ruleArgs(s routeSpec, op string) []string {
	args := []string{s.family, "rule", op, "priority", s.priority, "iif", "br-lan"}
	if s.mark != "" {
		args = append(args, "fwmark", s.mark+"/"+s.mark)
	}
	return append(args, "table", s.table)
}
func routeArgs(s routeSpec, op string) []string {
	args := []string{s.family, "route", op}
	if s.device == "" {
		args = append(args, "unreachable")
	}
	args = append(args, "default")
	if s.device != "" {
		args = append(args, "dev", s.device)
	}
	if s.metric != "" {
		args = append(args, "metric", s.metric)
	}
	return append(args, "table", s.table)
}
func tableEqual(v any, table string) bool {
	return text(v) == table || (table == "main" && text(v) == "254")
}
func ruleMatches(r map[string]any, s routeSpec) bool {
	if text(r["priority"]) != s.priority || !tableEqual(r["table"], s.table) || text(r["iif"]) != "br-lan" {
		return false
	}
	for key, value := range r {
		switch key {
		case "priority", "table", "iif":
		case "src":
			if text(value) != "all" {
				return false
			}
		case "flags":
			if len(list(value)) != 0 {
				return false
			}
		case "fwmark", "fwmask":
			if s.mark == "" {
				return false
			}
			n, ok := number(value)
			if !ok || n != 0x40000000 {
				return false
			}
		default:
			return false
		}
	}
	if s.mark != "" {
		a, _ := number(r["fwmark"])
		b, _ := number(r["fwmask"])
		return a == 0x40000000 && b == 0x40000000
	}
	return r["fwmark"] == nil && r["fwmask"] == nil
}
func routeMatches(r map[string]any, s routeSpec) bool {
	if text(r["dst"]) != "default" {
		return false
	}
	if s.device == "" {
		if text(r["type"]) != "unreachable" {
			return false
		}
	} else if text(r["dev"]) != s.device || (r["type"] != nil && text(r["type"]) != "unicast") {
		return false
	}
	metric := text(r["metric"])
	if s.metric == "" {
		if metric != "" && metric != "0" {
			return false
		}
	} else if metric != s.metric {
		return false
	}
	for key, value := range r {
		switch key {
		case "dst", "type", "dev", "metric":
		case "protocol":
			if text(value) != "boot" && text(value) != "static" {
				return false
			}
		case "flags":
			if len(list(value)) != 0 {
				return false
			}
		case "scope":
			if text(value) != "global" && text(value) != "link" {
				return false
			}
		case "table":
			if !tableEqual(value, s.table) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (c *controller) routing(fresh bool) error {
	return c.routingScope(fresh, false)
}
func (c *controller) routingScope(fresh, holdOnly bool) error {
	// Capture routing is IPv4-only. IPv6 routes and rules remain firmware-owned.
	for _, family := range []string{"-4"} {
		data, err := c.command("ip", family, "-j", "rule", "show")
		if err != nil {
			return err
		}
		value, err := decode(data)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, entry := range list(value) {
			r := object(entry)
			priority := text(r["priority"])
			if holdOnly && priority != "10073" {
				continue
			}
			if priority != "10073" && priority != "10074" && priority != "10075" {
				continue
			}
			if fresh || seen[priority] {
				return errors.New("reserved policy priority collision")
			}
			seen[priority] = true
			matched := false
			for _, s := range ruleSpecs {
				if s.family == family && ruleMatches(r, s) {
					matched = true
				}
			}
			if !matched {
				return errors.New("owned policy rule changed; review required")
			}
		}
		routes, err := c.routeSnapshot(family)
		if err != nil {
			return err
		}
		for _, table := range []string{"10073", "10074"} {
			if holdOnly && table != "10073" {
				continue
			}
			entries, err := routes.table(table)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if fresh {
					return errors.New("reserved route table collision")
				}
				matched := false
				for _, s := range routeSpecs {
					if s.family == family && s.table == table && routeMatches(object(entry), s) {
						matched = true
					}
				}
				if !matched {
					return errors.New("owned route table changed; review required")
				}
			}
		}
	}
	return nil
}
func (c *controller) routes(family, table string) ([]byte, error) {
	entries, err := c.routeTable(family, table)
	if err != nil {
		return nil, err
	}
	return json.Marshal(entries)
}

func (c *controller) routeTable(family, table string) ([]any, error) {
	if _, err := routeTableID(table); err != nil {
		return nil, err
	}
	snapshot, err := c.routeSnapshot(family)
	if err != nil {
		return nil, err
	}
	return snapshot.table(table)
}

type routeTableSnapshot struct {
	byID map[uint32][]any
}

func (snapshot *routeTableSnapshot) table(table string) ([]any, error) {
	wanted, err := routeTableID(table)
	if err != nil {
		return nil, err
	}
	if entries, ok := snapshot.byID[wanted]; ok {
		return entries, nil
	}
	return []any{}, nil
}

func (c *controller) routeSnapshot(family string) (*routeTableSnapshot, error) {
	// Some target iproute2 builds return exit 2 and truncated JSON for a table
	// that does not exist. A full dump succeeds without creating that table.
	data, err := c.runCommand("", "ip", family, "-j", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	entries, err := decodeCommandObjectList("ip", data)
	if err != nil {
		return nil, err
	}
	snapshot := &routeTableSnapshot{byID: make(map[uint32][]any)}
	for _, entry := range entries {
		route := object(entry)
		// ip omits the table field for main, not for the reserved project tables.
		id := uint32(254)
		if raw, exists := route["table"]; exists {
			id, err = routeTableID(raw)
			if err != nil {
				return nil, err
			}
		}
		snapshot.byID[id] = append(snapshot.byID[id], route)
	}
	return snapshot, nil
}

func routeTableID(value any) (uint32, error) {
	// Names emitted by this firmware's stock rt_tables file. Unknown aliases
	// cannot safely be assumed foreign: they might name a reserved table.
	switch text(value) {
	case "unspec":
		return 0, nil
	case "prelocal":
		return 128, nil
	case "default":
		return 253, nil
	case "main":
		return 254, nil
	case "local":
		return 255, nil
	}
	if id, ok := number(value); ok {
		return id, nil
	}
	return 0, fmt.Errorf("unrecognized route table identifier %v; review required", value)
}
func (c *controller) installRouting(hold bool) error {
	if err := c.routingScope(false, hold); err != nil {
		return err
	}
	for _, s := range routeSpecs {
		if s.hold != hold {
			continue
		}
		if err := c.ensureRoute(s); err != nil {
			return err
		}
	}
	for _, s := range ruleSpecs {
		if s.hold != hold {
			continue
		}
		if err := c.ensureRule(s); err != nil {
			return err
		}
	}
	return nil
}
func (c *controller) ensureRule(s routeSpec) error {
	data, err := c.command("ip", s.family, "-j", "rule", "show")
	if err != nil {
		return err
	}
	value, err := decode(data)
	if err != nil {
		return err
	}
	for _, entry := range list(value) {
		if ruleMatches(object(entry), s) {
			return nil
		}
	}
	return c.mutation("ip", ruleArgs(s, "add")...)
}
func (c *controller) ensureRoute(s routeSpec) error {
	entries, err := c.routeTable(s.family, s.table)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if routeMatches(object(entry), s) {
			return nil
		}
	}
	return c.mutation("ip", routeArgs(s, "add")...)
}
func (c *controller) removeRouting(hold bool) error {
	if err := c.routing(false); err != nil {
		return err
	}
	for _, s := range ruleSpecs {
		if s.hold != hold {
			continue
		}
		data, err := c.command("ip", s.family, "-j", "rule", "show")
		if err != nil {
			return err
		}
		value, err := decode(data)
		if err != nil {
			return err
		}
		for _, entry := range list(value) {
			if ruleMatches(object(entry), s) {
				if err = c.mutation("ip", ruleArgs(s, "del")...); err != nil {
					return err
				}
			}
		}
	}
	for _, s := range routeSpecs {
		if s.hold != hold {
			continue
		}
		entries, err := c.routeTable(s.family, s.table)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if routeMatches(object(entry), s) {
				if err = c.mutation("ip", routeArgs(s, "del")...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func parseServers(line string) ([]string, error) {
	pos := strings.Index(line, "=")
	if pos < 0 {
		return nil, errors.New("invalid UCI server list")
	}
	tail := line[pos+1:]
	re := regexp.MustCompile(`^'([^'\s]+)'(?: |$)`)
	values := []string{}
	for tail != "" {
		m := re.FindStringSubmatch(tail)
		if m == nil {
			return nil, errors.New("unusual server values require review")
		}
		values = append(values, m[1])
		tail = tail[len(m[0]):]
	}
	if len(values) == 0 {
		return nil, errors.New("empty server list requires review")
	}
	return values, nil
}
func validateDNS(d dnsOptions) error {
	if d.Noresolv != nil && *d.Noresolv != "0" && *d.Noresolv != "1" {
		return errors.New("invalid original noresolv")
	}
	for _, value := range d.Servers {
		if !regexp.MustCompile(`^[^'\s]+$`).MatchString(value) {
			return errors.New("invalid original DNS server")
		}
	}
	return nil
}
func (c *controller) readDNS() (dnsOptions, error) {
	var result dnsOptions
	// Probe option presence via an exported section, not by treating every UCI
	// read failure as a missing option (which would lose the recovery baseline).
	data, err := c.command("uci", "-q", "show", "dhcp.@dnsmasq[0]")
	if err != nil {
		return result, err
	}
	sectionFound := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasSuffix(line, "=dnsmasq") || strings.HasSuffix(line, "='dnsmasq'") {
			sectionFound = true
		}
		key := strings.SplitN(line, "=", 2)[0]
		if strings.HasSuffix(key, ".server") {
			result.Servers, err = parseServers(line)
			if err != nil {
				return result, err
			}
		}
		if strings.HasSuffix(key, ".noresolv") {
			pos := strings.Index(line, "=")
			if pos < 0 {
				return result, errors.New("bad noresolv")
			}
			value := strings.Trim(line[pos+1:], "'")
			result.Noresolv = &value
		}
	}
	if !sectionFound {
		return result, errors.New("DNS section read did not establish a recovery baseline")
	}
	return result, validateDNS(result)
}
func bridgeDNS() dnsOptions {
	value := "1"
	return dnsOptions{Noresolv: &value, Servers: []string{"127.0.0.1#15353"}}
}

func (c *controller) readDNSBaseline() (dnsOptions, error) {
	current, err := c.readDNS()
	if err == nil && reflect.DeepEqual(current, bridgeDNS()) {
		err = errors.New("unreferenced bridge DNS settings require review; retained without modification")
	}
	return current, err
}
func (c *controller) cleanUCI(config string) error {
	data, err := c.command("uci", "changes", config)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) != 0 {
		return fmt.Errorf("uncommitted %s changes require review", config)
	}
	return nil
}
func (c *controller) setDNS(current, next dnsOptions) error {
	if err := c.cleanUCI("dhcp"); err != nil {
		return err
	}
	lines := []string{}
	if len(current.Servers) != 0 {
		lines = append(lines, "delete dhcp.@dnsmasq[0].server")
	}
	if current.Noresolv != nil {
		lines = append(lines, "delete dhcp.@dnsmasq[0].noresolv")
	}
	if next.Noresolv != nil {
		lines = append(lines, "set dhcp.@dnsmasq[0].noresolv='"+*next.Noresolv+"'")
	}
	for _, server := range next.Servers {
		lines = append(lines, "add_list dhcp.@dnsmasq[0].server='"+server+"'")
	}
	lines = append(lines, "commit dhcp")
	// The caller's ownership check may precede routing/firewall cleanup. Do not
	// reuse that stale snapshot if the user changed either owned DNS option.
	latest, err := c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(latest, current) {
		return errors.New("DNS ownership changed before commit; settings retained")
	}
	if err := c.batch("uci", strings.Join(lines, "\n")+"\n", "batch"); err != nil {
		return err
	}
	after, err := c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(after, next) {
		return errors.New("DNS bridge commit did not match")
	}
	return c.mutation("/etc/init.d/dnsmasq", "restart")
}
func includeText() string {
	return "set firewall.sb_proxy_forward=include\nset firewall.sb_proxy_forward.type='nftables'\nset firewall.sb_proxy_forward.path='/etc/sing-box/forwarding.nft'\nset firewall.sb_proxy_forward.position='chain-pre'\nset firewall.sb_proxy_forward.chain='forward'\n" +
		"set firewall.sb_proxy_input=include\nset firewall.sb_proxy_input.type='nftables'\nset firewall.sb_proxy_input.path='/etc/sing-box/tun-input.nft'\nset firewall.sb_proxy_input.position='chain-pre'\nset firewall.sb_proxy_input.chain='input'\ncommit firewall\n"
}
func (c *controller) includePresent() (bool, error) {
	data, err := c.command("uci", "-q", "show", "firewall")
	if err != nil {
		return false, err
	}
	actual := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			continue
		}
		for _, section := range []string{includeSection, inputIncludeSection} {
			if pair[0] == section || strings.HasPrefix(pair[0], section+".") {
				actual[pair[0]] = strings.Trim(pair[1], "'")
			}
		}
	}
	if len(actual) == 0 {
		return false, nil
	}
	expected := map[string]string{}
	for _, include := range []struct{ section, file, chain string }{{includeSection, "forwarding.nft", "forward"}, {inputIncludeSection, "tun-input.nft", "input"}} {
		expected[include.section] = "include"
		expected[include.section+".type"] = "nftables"
		expected[include.section+".path"] = "/etc/sing-box/" + include.file
		expected[include.section+".position"] = "chain-pre"
		expected[include.section+".chain"] = include.chain
	}
	if !reflect.DeepEqual(actual, expected) {
		return false, errors.New("owned firewall include changed; review required")
	}
	return true, nil
}
func (c *controller) renderPolicy() ([]byte, error) {
	cacheMode, _, err := c.cacheModeMarker()
	if err != nil {
		return nil, err
	}
	data, err := c.command("ip", "-4", "-j", "address", "show", "dev", "br-lan")
	if err != nil {
		return nil, err
	}
	value, err := decode(data)
	if err != nil {
		return nil, err
	}
	prefixes := []string{}
	seen := map[string]bool{}
	routerAddresses := []string{}
	seenRouter := map[string]bool{}
	for _, iface := range list(value) {
		for _, entry := range list(object(iface)["addr_info"]) {
			a := object(entry)
			if text(a["family"]) != "inet" || text(a["scope"]) != "global" {
				continue
			}
			n, ok := number(a["prefixlen"])
			ip, e := netip.ParseAddr(text(a["local"]))
			if !ok || n > 32 || e != nil || !ip.Is4() {
				return nil, errors.New("invalid LAN address")
			}
			if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
				return nil, errors.New("invalid router IPv4 source address")
			}
			prefix := netip.PrefixFrom(ip, int(n)).Masked().String()
			if !seen[prefix] {
				seen[prefix] = true
				prefixes = append(prefixes, prefix)
			}
			address := ip.String()
			if !seenRouter[address] {
				seenRouter[address] = true
				routerAddresses = append(routerAddresses, address)
			}
		}
	}
	if len(prefixes) == 0 {
		return nil, errors.New("LAN addresses not ready")
	}
	data, err = os.ReadFile(filepath.Join(c.root, "routing-policy.nft"))
	if err != nil {
		return nil, err
	}
	if err = validateCapturePolicyMode(string(data), cacheMode); err != nil {
		return nil, err
	}
	if bytes.Count(data, []byte("__SB_LAN_PREFIXES__")) != 1 {
		return nil, errors.New("invalid LAN placeholder")
	}
	result := strings.ReplaceAll(string(data), "__SB_LAN_PREFIXES__", strings.Join(prefixes, ", "))
	routerPlaceholderCount := strings.Count(result, "__SB_ROUTER_ADDRESSES__")
	if cacheMode == cacheModeCTMark {
		if routerPlaceholderCount != 2 || len(routerAddresses) == 0 {
			return nil, errors.New("ctmark-v1 policy requires two router-address placeholders and a complete local IPv4 address list")
		}
		result = strings.ReplaceAll(result, "__SB_ROUTER_ADDRESSES__", strings.Join(routerAddresses, ", "))
	} else if routerPlaceholderCount != 0 {
		return nil, errors.New("cache-off policy unexpectedly contains a router-address cache placeholder")
	}
	// Both exceptions must be inserted before the system forward chain's flow-offload and reject
	// rules. A separate base-chain accept would not override the system policy.
	result += "insert rule inet fw4 forward iifname \"sb-tun\" oifname \"br-lan\" ct state { established, related } accept comment \"sing-box-from-tun\"\n"
	result += "insert rule inet fw4 forward iifname \"br-lan\" oifname \"sb-tun\" accept comment \"sing-box-to-tun\"\n"
	result += "insert rule inet fw4 input iifname \"sb-tun\" ip saddr 172.28.255.2 ip daddr 172.28.255.1 meta l4proto tcp ct state { new, established } accept comment \"sing-box-tun-tcp-input\"\n"
	return []byte(result), nil
}
func (c *controller) preflight() ([]byte, error) {
	if err := c.verified(); err != nil {
		return nil, err
	}
	for _, name := range []string{"mosdns.pid", "sing-box.pid", "core.pid"} {
		path := filepath.Join(c.state, name)
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("retained runtime PID record requires review: %s", name)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if _, err := c.command("fw4", "print"); err != nil {
		return nil, fmt.Errorf("OpenWrt firewall environment required: %w", err)
	}
	if _, err := c.command("nft", "--version"); err != nil {
		return nil, err
	}
	links, err := c.command("ip", "-j", "link", "show")
	if err != nil {
		return nil, err
	}
	linkValue, err := decode(links)
	if err != nil {
		return nil, err
	}
	for _, entry := range list(linkValue) {
		if text(object(entry)["ifname"]) == "sb-tun" {
			return nil, errors.New("pre-existing sb-tun requires review before activation")
		}
	}
	if err := c.rejectLegacyIntegration(); err != nil {
		return nil, err
	}
	if err := c.routing(true); err != nil {
		return nil, err
	}
	present, err := c.tablePresent()
	if err != nil {
		return nil, err
	}
	if present {
		return nil, errors.New("owned nft table name collision")
	}
	rules, err := c.forwardRules()
	if err != nil {
		return nil, err
	}
	if len(rules) != 0 {
		return nil, errors.New("forward rule comment collision")
	}
	if err = c.cleanUCI("firewall"); err != nil {
		return nil, err
	}
	if err = c.cleanUCI("dhcp"); err != nil {
		return nil, err
	}
	if _, err = c.readDNSBaseline(); err != nil {
		return nil, err
	}
	present, err = c.includePresent()
	if err != nil {
		return nil, err
	}
	if present {
		return nil, errors.New("firewall include already exists without this startup journal")
	}
	data, err := c.command("nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	value, err := decode(data)
	if err != nil {
		return nil, err
	}
	if err = checkMarkWrites(value); err != nil {
		return nil, err
	}
	policy, err := c.renderPolicy()
	if err != nil {
		return nil, err
	}
	if err = c.batch("nft", string(policy), "--check", "-f", "-"); err != nil {
		return nil, fmt.Errorf("target nft capabilities rejected policy: %w", err)
	}
	return policy, nil
}
func (c *controller) prepare() error {
	if err := c.requireGuardedCacheLifecycle(); err != nil {
		return err
	}
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return cacheGuardError("%v", err)
	}
	if mode == cacheModeCTMark {
		if err = c.refreshCacheAuthorization(); err != nil {
			return err
		}
	}
	if err := c.invalidateCacheProofForOffMode(); err != nil {
		return fmt.Errorf("invalidate inactive cache proof: %w", err)
	}
	if err := directory(c.state); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(c.state, "journal.json.write")); err == nil {
		return errors.New("journal write fragment retained; review required")
	} else if !os.IsNotExist(err) {
		return err
	}
	boot, err := c.boot()
	if err != nil {
		return err
	}
	journalPath := filepath.Join(c.state, "journal.json")
	if _, err = os.Lstat(journalPath); err == nil {
		j, e := c.load()
		if e != nil {
			return e
		}
		if j.Boot != boot {
			if e = c.clearStaleCorePIDRecords(); e != nil {
				return e
			}
		}
		if j.Phase != "restored" && j.Boot == boot {
			return errors.New("incomplete same-boot lifecycle; explicit stop/review required")
		}
		if j.Phase != "restored" {
			if e = c.stop(); e != nil {
				return e
			}
		}
		if e = c.ensureNoRuntimePolicy(); e != nil {
			return e
		}
		if e = os.Remove(journalPath); e != nil {
			return e
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err = c.ensureNoRuntimePolicy(); err != nil {
		return err
	}
	policy, err := c.preflight()
	if err != nil {
		return err
	}
	oldDNS, err := c.readDNSBaseline()
	if err != nil {
		return err
	}
	j := &journal{Version: 1, Boot: boot, Phase: "prepared", DNS: oldDNS}
	if err = c.save(j); err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(c.state, "runtime.nft"), policy); err != nil {
		return err
	}
	if err = c.installRouting(true); err != nil {
		return err
	}
	return nil
}
func (c *controller) apply() error {
	if err := c.requireGuardedCacheLifecycle(); err != nil {
		return err
	}
	if err := c.validateCacheAuthorizationBeforeApply(); err != nil {
		return err
	}
	j, err := c.load()
	if err != nil {
		return err
	}
	if j.Phase != "prepared" {
		return errors.New("apply requires prepared, ready dual-core lifecycle")
	}
	if err = c.verified(); err != nil {
		return err
	}
	if err = c.coreRunning(); err != nil {
		return err
	}
	for _, stage := range []string{"mosdns-direct-node", "sing-box-tun", "proxy-dns"} {
		ready, readyErr := c.readiness(stage)
		if readyErr != nil {
			return fmt.Errorf("%s readiness check: %w", stage, readyErr)
		}
		if !ready {
			return fmt.Errorf("%s is not ready", stage)
		}
	}
	if _, err = c.command("ip", "link", "show", "dev", "sb-tun"); err != nil {
		return err
	}
	current, err := c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, j.DNS) || reflect.DeepEqual(current, bridgeDNS()) {
		return errors.New("dnsmasq server/noresolv changed before apply")
	}
	if err = c.cleanUCI("firewall"); err != nil {
		return err
	}
	present, err := c.includePresent()
	if err != nil {
		return err
	}
	if present {
		return errors.New("include collision during apply")
	}
	present, err = c.tablePresent()
	if err != nil {
		return err
	}
	if present {
		return errors.New("nft table collision during apply")
	}
	rules, err := c.forwardRules()
	if err != nil {
		return err
	}
	if len(rules) != 0 {
		return errors.New("forward collision during apply")
	}
	// Recheck foreign writers after the core starts, including any competing
	// auto_redirect owner; no overlapping packet-capture backend is permitted.
	data, err := c.command("nft", "-j", "list", "ruleset")
	if err != nil {
		return err
	}
	value, err := decode(data)
	if err != nil {
		return err
	}
	if err = checkMarkWrites(value); err != nil {
		return err
	}
	if err = regular(filepath.Join(c.state, "runtime.nft")); err != nil {
		return err
	}
	policy, err := os.ReadFile(filepath.Join(c.state, "runtime.nft"))
	if err != nil {
		return err
	}
	expected, err := c.renderPolicy()
	if err != nil {
		return err
	}
	if !bytes.Equal(policy, expected) {
		return errors.New("prepared policy or LAN topology changed")
	}
	// Install and snapshot the kernel-normalized policy while its base chains
	// are disabled. Both fw4 exceptions only match the owned TUN interface.
	// No persistent include, DNS bridge or capture route exists at this point.
	const tableHeader = "table inet sb_proxy {"
	if bytes.Count(policy, []byte(tableHeader)) != 1 {
		return errors.New("prepared policy has no unique capture table")
	}
	draft := strings.Replace(string(policy), tableHeader, "create "+tableHeader+"\n    flags dormant;", 1)
	if err = c.batch("nft", draft, "--check", "-f", "-"); err != nil {
		return err
	}
	j.Phase = "nft-staging"
	if err = c.save(j); err != nil {
		return err
	}
	if err = c.batch("nft", draft, "-f", "-"); err != nil {
		return err
	}
	if err = c.requireCaptureTableState(true); err != nil {
		return err
	}
	j.NFT, err = c.captureTableSnapshot(true)
	if err != nil {
		return err
	}
	rules, err = c.forwardRules()
	if err != nil {
		return err
	}
	if len(rules) != 3 {
		return errors.New("incomplete owned forwarding exceptions")
	}
	j.Forward, err = forwardSnapshot(rules)
	if err != nil {
		return err
	}
	// Both exact snapshots must be durable before enabling capture or
	// changing DNS. The DNS phase also supports legacy recovery journals.
	j.Phase = "dns"
	j.DNSRestartPending = true
	if err = c.save(j); err != nil {
		return err
	}
	if err = c.setDNS(current, bridgeDNS()); err != nil {
		return err
	}
	if err = c.installRouting(false); err != nil {
		return err
	}
	if err = c.cleanUCI("firewall"); err != nil {
		return err
	}
	present, err = c.includePresent()
	if err != nil {
		return err
	}
	if present {
		return errors.New("include collision during apply")
	}
	if err = c.batch("uci", includeText(), "batch"); err != nil {
		return err
	}
	if err = c.prepareCacheProof(); err != nil {
		return err
	}
	if err = c.batch("nft", "add table inet sb_proxy\n", "-f", "-"); err != nil {
		return err
	}
	if err = c.requireCaptureTableState(false); err != nil {
		return err
	}
	j.Phase = "installed"
	if err = c.save(j); err != nil {
		return err
	}
	if err = c.inspectState(true); err != nil {
		return err
	}
	if err = c.removeRouting(true); err != nil {
		return err
	}
	j.Phase = "active"
	if err = c.save(j); err != nil {
		return err
	}
	return c.commitCacheProof()
}
func (c *controller) readiness(stage string) (bool, error) {
	if c.readyCheck != nil {
		return c.readyCheck(stage)
	}
	return c.lifecycleReady(stage)
}
func (c *controller) inspect() error { return c.inspectState(false) }
func (c *controller) inspectState(held bool) error {
	j, err := c.load()
	if err != nil {
		return err
	}
	if (!held && j.Phase != "active") || (held && j.Phase != "installed") {
		return errors.New("capture is not active")
	}
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return cacheGuardError("%v", err)
	}
	if !held && mode == cacheModeCTMark {
		if err = c.validateActiveCacheProof(j); err != nil {
			return err
		}
	}
	if err = c.verified(); err != nil {
		return err
	}
	if err = c.coreRunning(); err != nil {
		return err
	}
	prepared, err := os.ReadFile(filepath.Join(c.state, "runtime.nft"))
	if err != nil {
		return err
	}
	rendered, err := c.renderPolicy()
	if err != nil {
		return err
	}
	if !bytes.Equal(prepared, rendered) {
		return errors.New("LAN topology or prepared policy changed; review/restart required")
	}
	if err = c.routing(false); err != nil {
		return err
	}
	data, err := c.tableSnapshot()
	if err != nil {
		return err
	}
	if !bytes.Equal(data, j.NFT) {
		return errors.New("owned nft table changed; review required")
	}
	rules, err := c.forwardRules()
	if err != nil {
		return err
	}
	data, err = forwardSnapshot(rules)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, j.Forward) {
		return errors.New("owned forwarding exceptions changed; review required")
	}
	present, err := c.includePresent()
	if err != nil {
		return err
	}
	if !present {
		return errors.New("owned firewall include missing")
	}
	dns, err := c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(dns, bridgeDNS()) {
		return errors.New("owned DNS bridge changed; review required")
	}
	// Presence is a separate requirement: routing(false) permits missing own
	// objects only so a interrupted startup/exit can recover safely.
	for _, s := range ruleSpecs {
		if s.hold {
			continue
		}
		data, err = c.command("ip", s.family, "-j", "rule", "show")
		if err != nil {
			return err
		}
		value, e := decode(data)
		if e != nil {
			return e
		}
		found := false
		for _, r := range list(value) {
			if ruleMatches(object(r), s) {
				found = true
			}
		}
		if !found {
			return errors.New("owned policy rule missing")
		}
	}
	routeSnapshots := map[string]*routeTableSnapshot{}
	for _, s := range routeSpecs {
		if _, exists := routeSnapshots[s.family]; exists {
			continue
		}
		routeSnapshots[s.family], err = c.routeSnapshot(s.family)
		if err != nil {
			return err
		}
	}
	for _, s := range routeSpecs {
		entries, routeErr := routeSnapshots[s.family].table(s.table)
		if routeErr != nil {
			return routeErr
		}
		found := false
		for _, r := range entries {
			if routeMatches(object(r), s) {
				found = true
			}
		}
		if (s.hold && found != held) || (!s.hold && !found) {
			return errors.New("owned policy route missing or startup hold still present")
		}
	}
	for _, s := range ruleSpecs {
		if !s.hold {
			continue
		}
		data, err = c.command("ip", s.family, "-j", "rule", "show")
		if err != nil {
			return err
		}
		value, e := decode(data)
		if e != nil {
			return e
		}
		found := false
		for _, r := range list(value) {
			if ruleMatches(object(r), s) {
				found = true
			}
		}
		if found != held {
			return errors.New("startup hold state does not match capture state")
		}
	}
	return nil
}
func (c *controller) stop() error {
	j, err := c.load()
	if os.IsNotExist(err) {
		if err = c.noOwnedObjects(); err != nil {
			return err
		}
		_, err = c.readDNSBaseline()
		return err
	}
	if err != nil {
		return err
	}
	cacheStopAuthorization := c.captureCacheStopAuthorization(j)
	if j.Phase == "restored" {
		if err = c.ensureNoRuntimePolicy(); err != nil {
			return err
		}
		if err = c.noOwnedObjects(); err != nil {
			return err
		}
		return c.refreshCacheProofAfterRestore(j, cacheStopAuthorization)
	}
	if err = c.noCorePIDRecords(); err != nil {
		return err
	}
	if j.Phase == "nft-staging" {
		// A failure before the snapshots were durable can leave inert nft
		// objects. Restore native forwarding by removing only the independently
		// verified startup hold. Preserve unsigned objects for review.
		if err = c.removeRouting(true); err != nil {
			return err
		}
		if err = c.removeRuntimePolicy(); err != nil {
			return err
		}
		if err = c.noOwnedObjects(); err != nil {
			return fmt.Errorf("startup hold released; unfinished nft staging requires review: %w", err)
		}
		if _, err = c.readDNSBaseline(); err != nil {
			return err
		}
		j.Phase = "restored"
		return c.save(j)
	}
	if err = c.installRouting(true); err != nil {
		return err
	}
	// A collision in the capture table must not prevent installing the separate
	// hold, but all namespaces must be rechecked before deleting any integration.
	if err = c.routing(false); err != nil {
		return err
	}
	present, err := c.tablePresent()
	if err != nil {
		return err
	}
	if present {
		// In the DNS phase the durably recorded table may still be dormant,
		// or the enable command may have committed before returning an error.
		data, e := c.captureTableSnapshot(j.Phase == "dns" && len(j.NFT) != 0)
		if e != nil {
			return e
		}
		if len(j.NFT) == 0 || !bytes.Equal(data, j.NFT) {
			return errors.New("unverified or changed nft table retained under hold; review required")
		}
	}
	rules, err := c.forwardRules()
	if err != nil {
		return err
	}
	if len(rules) != 0 {
		data, e := forwardSnapshot(rules)
		if e != nil {
			return e
		}
		if len(j.Forward) == 0 || !bytes.Equal(data, j.Forward) {
			return errors.New("unverified or changed forwarding exceptions retained; review required")
		}
	}
	if err = c.cleanUCI("firewall"); err != nil {
		return err
	}
	if err = c.cleanUCI("dhcp"); err != nil {
		return err
	}
	include, err := c.includePresent()
	if err != nil {
		return err
	}
	current, err := c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, bridgeDNS()) && !reflect.DeepEqual(current, j.DNS) {
		return errors.New("DNS ownership conflict; retained protection and recovery baseline")
	}
	// Remove only the exact recorded handles and the single owned table. nft's
	// transaction does not flush or recreate the system firewall table.
	lines := []string{}
	for _, entry := range rules {
		r := object(entry)
		handle, ok := number(r["handle"])
		if !ok || handle == 0 {
			return errors.New("invalid owned forwarding rule handle")
		}
		chain := text(r["chain"])
		if chain != "forward" && chain != "input" {
			return errors.New("invalid owned firewall rule chain")
		}
		lines = append(lines, fmt.Sprintf("delete rule inet fw4 %s handle %d", chain, handle))
	}
	if present {
		lines = append(lines, "delete table inet sb_proxy")
	}
	if len(lines) != 0 {
		if err = c.batch("nft", strings.Join(lines, "\n")+"\n", "-f", "-"); err != nil {
			return err
		}
	}
	if include {
		if err = c.batch("uci", "delete "+includeSection+"\ndelete "+inputIncludeSection+"\ncommit firewall\n", "batch"); err != nil {
			return err
		}
	}
	if err = c.removeRouting(false); err != nil {
		return err
	}
	if j.DNSRestartPending || !reflect.DeepEqual(current, j.DNS) {
		if !j.DNSRestartPending {
			j.DNSRestartPending = true
			if err = c.save(j); err != nil {
				return err
			}
		}
		if reflect.DeepEqual(current, j.DNS) {
			err = c.mutation("/etc/init.d/dnsmasq", "restart")
		} else {
			err = c.setDNS(current, j.DNS)
		}
		if err != nil {
			return err
		}
	}
	// Re-read exactly the two DNS options; other DHCP settings are never
	// restored from a whole-config snapshot or treated as a health gate.
	current, err = c.readDNS()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, j.DNS) {
		return errors.New("DNS options not restored")
	}
	if err = c.removeRouting(true); err != nil {
		return err
	}
	if err = c.removeRuntimePolicy(); err != nil {
		return err
	}
	if err = c.noOwnedObjects(); err != nil {
		return err
	}
	// The original network is already restored even if persisting this
	// final record fails. A retry may safely repeat the DNS restart.
	j.DNSRestartPending = false
	j.Phase = "restored"
	if err = c.save(j); err != nil {
		return err
	}
	return c.refreshCacheProofAfterRestore(j, cacheStopAuthorization)
}

func (c *controller) removeRuntimePolicy() error {
	path := filepath.Join(c.state, "runtime.nft")
	if err := regular(path); err == nil {
		return os.Remove(path)
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}

func (c *controller) ensureNoRuntimePolicy() error {
	path := filepath.Join(c.state, "runtime.nft")
	if err := regular(path); err == nil {
		return errors.New("unreferenced runtime policy retained; review required")
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}

func (c *controller) noOwnedObjects() error {
	if err := c.ensureNoRuntimePolicy(); err != nil {
		return err
	}
	if err := c.noCorePIDRecords(); err != nil {
		return err
	}
	if err := c.routing(true); err != nil {
		return err
	}
	present, err := c.tablePresent()
	if err != nil {
		return err
	}
	if present {
		return errors.New("unreferenced nft table retained; review required")
	}
	rules, err := c.forwardRules()
	if err != nil {
		return err
	}
	if len(rules) != 0 {
		return errors.New("unreferenced forwarding exceptions retained; review required")
	}
	present, err = c.includePresent()
	if err != nil {
		return err
	}
	if present {
		return errors.New("unreferenced firewall include retained; review required")
	}
	return nil
}

func (c *controller) noCorePIDRecords() error {
	for _, name := range []string{"mosdns.pid", "sing-box.pid", "core.pid"} {
		path := filepath.Join(c.state, name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("runtime PID record remains; lifecycle owner must stop cores first: %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// clearStaleCorePIDRecords is only called after a valid journal proves that
// the recorded processes belong to a previous boot. Validate the entire set
// before unlinking anything; legacy core.pid remains an ownership conflict.
func (c *controller) clearStaleCorePIDRecords() error {
	legacy := filepath.Join(c.state, "core.pid")
	if err := regular(legacy); err == nil {
		return errors.New("legacy core PID record has unknown ownership; retained for review")
	} else if !os.IsNotExist(err) {
		return err
	}

	paths := []string{}
	for _, name := range []string{"mosdns.pid", "sing-box.pid"} {
		path := filepath.Join(c.state, name)
		if err := regular(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		value := strings.TrimSpace(string(data))
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 0 || strconv.Itoa(pid) != value {
			return fmt.Errorf("invalid old-boot %s record; retained for review", name)
		}
		paths = append(paths, path)
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale owned PID record %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// Link a prepared executable to the exact path, with the kernel's no-clobber
// semantics even when the path already names a directory.
func publishInstallInit(root, destination string) error {
	if err := directory(root); err != nil {
		return err
	}
	if err := directory(filepath.Dir(destination)); err != nil {
		return err
	}
	staged := filepath.Join(root, ".install-init")
	if err := regular(staged); err != nil {
		return err
	}
	return os.Link(staged, destination)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: sb-controller verify-cores|legacy-check|publish-install-init|preflight|prepare|apply|inspect|stop|supervise|service-start|service-status|service-rollback|cache-boot-check|stage-cache-receipt|cache-rollback-clean")
		os.Exit(2)
	}
	action := os.Args[1]
	c := &controller{root: "/etc/sing-box", state: "/etc/sing-box-state", boot: func() (string, error) {
		b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		return strings.TrimSpace(string(b)), e
	}}
	var err error
	if action == "stage-cache-receipt" {
		err = stageCacheReceiptCLI(c, os.Args[2:])
	} else if len(os.Args) != 2 {
		err = errors.New("this controller action does not accept arguments")
	} else {
		switch action {
		case "verify-cores":
			err = c.verifyExternalCores()
		case "legacy-check":
			err = c.rejectLegacyIntegration()
		case "publish-install-init":
			err = publishInstallInit(c.root, "/etc/init.d/sing-box")
		case "service-start", "service-status", "service-rollback":
			err = c.serviceLockAction(action)
		case "cache-boot-check":
			err = c.cacheBootCheck()
		case "preflight":
			_, err = c.preflight()
		case "inspect":
			err = c.inspect()
		case "prepare", "apply", "stop", "supervise", "cache-rollback-clean":
			if err = directory(c.state); err == nil {
				err = regular(filepath.Join(c.state, "owner"))
				if err == nil {
					var data []byte
					data, err = os.ReadFile(filepath.Join(c.state, "owner"))
					if err == nil && string(data) != "sing-box-native-v1\n" {
						err = errors.New("unknown integration owner")
					}
				}
				if err == nil {
					var unlock func()
					unlock, err = lockFile(filepath.Join(c.state, "controller.lock"))
					if err == nil {
						defer unlock()
						switch os.Args[1] {
						case "prepare":
							err = c.prepare()
						case "apply":
							err = c.apply()
						case "stop":
							err = c.stop()
						case "cache-rollback-clean":
							err = c.cacheRollbackClean()
						case "supervise":
							c.cacheLifecycleAuthorized = true
							var ctx context.Context
							var cancel context.CancelFunc
							ctx, cancel = newSignalContext()
							defer cancel()
							err = c.supervise(ctx)
						}
					}
				}
			}
		default:
			err = errors.New("unknown action")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitCode := 1
		var recoveryOnly recoveryOnlyError
		if action == "cache-boot-check" && errors.As(err, &recoveryOnly) {
			exitCode = 2
		}
		os.Exit(exitCode)
	}
	fmt.Println("SING_BOX_" + strings.ToUpper(action) + "_OK")
}
