package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	directDomainFile        = "dns-direct-domains.txt"
	rejectDomainFile        = "dns-reject-domains.txt"
	startupTimeout          = 30 * time.Second
	startupRetry            = 250 * time.Millisecond
	networkReadinessTimeout = 30 * time.Second
	networkReadinessRetry   = time.Second
	probeTimeout            = 5 * time.Second
)

type dnsDomainRule struct {
	name    string
	kind    string
	pattern *regexp.Regexp
}

type dnsProbeNames struct {
	direct     string
	haveDirect bool
	node       string
	proxy      string
	proxyErr   string
}

type domainProbeCache struct {
	mu         sync.Mutex
	digest     [2][32]byte
	names      dnsProbeNames
	valid      bool
	hashBuffer []byte
}

func (cache *domainProbeCache) resolve(digest [2][32]byte, build func() (dnsProbeNames, error)) (dnsProbeNames, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.resolveLocked(digest, build)
}

func (cache *domainProbeCache) resolveLocked(digest [2][32]byte, build func() (dnsProbeNames, error)) (dnsProbeNames, error) {
	if cache.valid && cache.digest == digest {
		return cache.names, nil
	}
	cache.valid = false
	cache.digest = [2][32]byte{}
	cache.names = dnsProbeNames{}
	names, err := build()
	if err != nil {
		return dnsProbeNames{}, err
	}
	cache.digest = digest
	cache.names = names
	cache.valid = true
	return names, nil
}

func buildDNSProbeNames(directData, rejectData []byte) (dnsProbeNames, error) {
	rules, err := parseDNSDomainRules(directData)
	if err != nil {
		return dnsProbeNames{}, fmt.Errorf("%s: %w", directDomainFile, err)
	}
	rejectRules, err := parseDNSDomainRules(rejectData)
	if err != nil {
		return dnsProbeNames{}, fmt.Errorf("%s: %w", rejectDomainFile, err)
	}
	rejected := newDNSRejectMatcher(rejectRules)
	direct, haveDirect := directProbeName(rules, rejected)
	// Full names may point into the parser's shared source string.
	direct = strings.Clone(direct)
	node := direct
	if !haveDirect {
		node = reservedDNSProbeName(nil, rejected)
	}
	proxy := reservedDNSProbeName(rules, rejected)
	names := dnsProbeNames{direct: direct, haveDirect: haveDirect, node: node, proxy: proxy}
	if proxy == "" {
		// A valid payload can still lack a probe that exercises the proxy branch.
		names.proxyErr = "no reserved proxy DNS probe name remains outside the direct and reject domain rules"
	}
	return names, nil
}

type dnsProbeRuleFile struct {
	path   string
	file   *os.File
	info   os.FileInfo
	digest [32]byte
}

func (input dnsProbeRuleFile) verify() error {
	if input.file != nil {
		return verifyOpenedRegularFile(input.path, input.file, input.info)
	}
	_, err := os.Lstat(input.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("DNS domain rules appeared while loading: %s", input.path)
}

func (input dnsProbeRuleFile) read() ([]byte, error) {
	if input.file == nil {
		return nil, nil
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(input.file)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(data) != input.digest {
		return nil, fmt.Errorf("DNS domain rules changed while loading: %s", input.path)
	}
	return data, nil
}

func (c *controller) dnsProbeNames() (names dnsProbeNames, resultErr error) {
	cache := &c.domainProbes
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.hashBuffer == nil {
		cache.hashBuffer = make([]byte, payloadHashBufferSize)
	}
	var inputs [2]dnsProbeRuleFile
	var digest [2][32]byte
	for index, name := range [2]string{directDomainFile, rejectDomainFile} {
		path := filepath.Join(c.root, name)
		inputs[index].path = path
		file, info, err := openRegularFile(path)
		if name == rejectDomainFile && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return dnsProbeNames{}, err
		}
		defer func() {
			if err := file.Close(); err != nil {
				resultErr = appendError(resultErr, fmt.Errorf("close DNS domain rules %s: %w", path, err))
			}
		}()
		digest[index], err = streamSHA256(file, cache.hashBuffer)
		if err != nil {
			return dnsProbeNames{}, fmt.Errorf("digest DNS domain rules %s: %w", path, err)
		}
		inputs[index] = dnsProbeRuleFile{path: path, file: file, info: info, digest: digest[index]}
		if err = inputs[index].verify(); err != nil {
			return dnsProbeNames{}, err
		}
	}
	names, err := cache.resolveLocked(digest, func() (dnsProbeNames, error) {
		direct, err := inputs[0].read()
		if err != nil {
			return dnsProbeNames{}, err
		}
		reject, err := inputs[1].read()
		if err != nil {
			return dnsProbeNames{}, err
		}
		return buildDNSProbeNames(direct, reject)
	})
	if err != nil {
		return dnsProbeNames{}, err
	}
	for _, input := range inputs {
		if err = input.verify(); err != nil {
			cache.valid = false
			cache.digest = [2][32]byte{}
			cache.names = dnsProbeNames{}
			return dnsProbeNames{}, err
		}
	}
	return names, nil
}

func parseDNSDomainRules(data []byte) ([]dnsDomainRule, error) {
	rules := []dnsDomainRule{}
	for lineNumber, line := range strings.Split(strings.TrimPrefix(string(data), "\uFEFF"), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		separator := strings.IndexByte(line, ':')
		if separator <= 0 {
			return nil, fmt.Errorf("line %d requires a MosDNS full:, domain:, or regexp: rule", lineNumber+1)
		}
		kind, ruleValue := line[:separator], line[separator+1:]
		if kind == "regexp" {
			if ruleValue == "" || len(ruleValue) > 1_000_000 {
				return nil, fmt.Errorf("line %d has an empty or oversized regexp", lineNumber+1)
			}
			pattern, err := regexp.Compile(ruleValue)
			if err != nil {
				return nil, fmt.Errorf("line %d has an invalid regexp: %w", lineNumber+1, err)
			}
			rules = append(rules, dnsDomainRule{name: ruleValue, kind: kind, pattern: pattern})
			continue
		}
		if kind != "full" && kind != "domain" {
			return nil, fmt.Errorf("line %d uses unsupported MosDNS matcher %q", lineNumber+1, kind)
		}
		ruleValue = strings.TrimSuffix(strings.ToLower(ruleValue), ".")
		if !validDNSName(ruleValue) {
			return nil, fmt.Errorf("line %d contains an invalid domain", lineNumber+1)
		}
		rules = append(rules, dnsDomainRule{name: ruleValue, kind: kind})
	}
	return rules, nil
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
				return false
			}
		}
	}
	return true
}

func (r dnsDomainRule) matches(name string) bool {
	// MosDNS NormalizeDomain lowercases and removes one terminal dot before
	// each matcher, including regex. Keep the regexp source unchanged.
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	switch r.kind {
	case "full":
		return name == r.name
	case "domain":
		return name == r.name || strings.HasSuffix(name, "."+r.name)
	case "regexp":
		return r.pattern != nil && r.pattern.MatchString(name)
	default:
		return false
	}
}

func validateSingBoxPayload(data []byte) error {
	value, err := decode(data)
	if err != nil {
		return fmt.Errorf("invalid sing-box JSON: %w", err)
	}
	config := object(value)
	if config == nil {
		return errors.New("sing-box config must be an object")
	}
	inbounds := list(config["inbounds"])
	if len(inbounds) != 2 {
		return errors.New("sing-box must contain only the TUN and local DNS SOCKS inbounds")
	}
	tunFound, socksFound := false, false
	for _, item := range inbounds {
		inbound := object(item)
		if inbound == nil {
			return errors.New("invalid sing-box inbound")
		}
		switch text(inbound["type"]) {
		case "tun":
			if tunFound || text(inbound["interface_name"]) != "sb-tun" || text(inbound["dns_mode"]) != "disabled" {
				return errors.New("sing-box TUN must use sb-tun with DNS mode disabled")
			}
			if !explicitFalse(inbound, "auto_route") || !explicitFalse(inbound, "auto_redirect") {
				return errors.New("sing-box TUN auto_route and auto_redirect must be explicitly false")
			}
			if _, exists := inbound["multi_queue"]; exists {
				return errors.New("unsupported TUN multi_queue field")
			}
			if text(inbound["stack"]) != "mixed" || !reflect.DeepEqual(list(inbound["address"]), []any{"172.28.255.1/30"}) {
				return errors.New("mixed TCP input integration requires the fixed 172.28.255.1/30 TUN address")
			}
			tunFound = true
		case "socks":
			port, ok := number(inbound["listen_port"])
			if socksFound || text(inbound["tag"]) != "dns-proxy-in" || text(inbound["listen"]) != "127.0.0.1" || !ok || port != 15355 {
				return errors.New("sing-box DNS SOCKS inbound must listen on 127.0.0.1:15355")
			}
			socksFound = true
		default:
			return errors.New("unexpected sing-box inbound")
		}
	}
	if !tunFound || !socksFound {
		return errors.New("sing-box TUN or DNS SOCKS inbound is missing")
	}
	route := object(config["route"])
	rules := list(route["rules"])
	resolver := object(route["default_domain_resolver"])
	if text(route["final"]) != "proxy" || len(resolver) != 3 ||
		text(resolver["server"]) != "node-dns" || text(resolver["strategy"]) != "ipv4_only" || text(resolver["timeout"]) != "5s" || len(rules) != 1 {
		return errors.New("sing-box route must contain only IPv6 rejection and default proxy")
	}
	if _, exists := route["rule_set"]; exists {
		return errors.New("sing-box business route rule sets are not permitted")
	}
	proxyFound := false
	for _, item := range list(config["outbounds"]) {
		if text(object(item)["tag"]) == "proxy" {
			proxyFound = true
			break
		}
	}
	if !proxyFound {
		return errors.New("sing-box default proxy outbound tag is missing")
	}
	rule := object(rules[0])
	version, ok := number(rule["ip_version"])
	method, hasMethod := rule["method"]
	noDrop, hasNoDrop := rule["no_drop"]
	validMethod := len(rule) == 2 || (len(rule) == 4 && hasMethod && text(method) == "default" && hasNoDrop && noDrop == true)
	if !ok || version != 6 || text(rule["action"]) != "reject" || !validMethod {
		return errors.New("sing-box's only business route rule must reject IPv6")
	}
	dns := object(config["dns"])
	if dns == nil || text(dns["final"]) != "node-dns" || text(dns["strategy"]) != "ipv4_only" || !explicitTrue(dns, "disable_cache") {
		return errors.New("sing-box DNS client must be the uncached IPv4-only node resolver")
	}
	servers := list(dns["servers"])
	if len(servers) != 1 {
		return errors.New("sing-box must use exactly one node DNS server")
	}
	server := object(servers[0])
	port, ok := number(server["server_port"])
	if text(server["type"]) != "udp" || text(server["tag"]) != "node-dns" || text(server["server"]) != "127.0.0.1" || !ok || port != 15354 {
		return errors.New("sing-box node DNS server must be mosdns at 127.0.0.1:15354/UDP")
	}
	return nil
}

func explicitFalse(value map[string]any, key string) bool {
	item, exists := value[key]
	if !exists {
		return false
	}
	result, ok := item.(bool)
	return ok && !result
}

func explicitTrue(value map[string]any, key string) bool {
	item, exists := value[key]
	if !exists {
		return false
	}
	result, ok := item.(bool)
	return ok && result
}

func (c *controller) validateMosdnsPayload() error {
	configPath := filepath.Join(c.root, "mosdns.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	if err = validateMosdnsBindings(data); err != nil {
		return err
	}
	if !strings.Contains(string(data), "dns-direct-domains.txt") {
		return errors.New("mosdns config does not reference dns-direct-domains.txt")
	}
	if _, err = c.dnsProbeNames(); err != nil {
		return err
	}
	return nil
}

func validateMosdnsBindings(data []byte) error {
	const ordinary = "127.0.0.1:15353"
	const node = "127.0.0.1:15354"
	const metrics = "127.0.0.1:15357"
	sections := map[string]int{}
	apiValues := []string{}
	listenCounts := map[string]int{}
	serverCounts := map[string]map[string]int{}
	section := ""
	pluginType := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			key, value, found := strings.Cut(trimmed, ":")
			if !found || strings.TrimSpace(value) != "" {
				section = ""
				pluginType = ""
				continue
			}
			section = strings.TrimSpace(key)
			sections[section]++
			pluginType = ""
			continue
		}
		if section == "api" {
			if indent != 2 {
				return errors.New("mosdns api configuration must contain only a single-level http address")
			}
			key, value, found := strings.Cut(trimmed, ":")
			if !found || strings.TrimSpace(key) != "http" {
				return errors.New("mosdns api configuration contains an unsupported option")
			}
			value = strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
			apiValues = append(apiValues, strings.Trim(value, "\"'"))
			continue
		}
		if section != "plugins" {
			continue
		}
		if indent == 2 && strings.HasPrefix(trimmed, "- ") {
			pluginType = ""
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if key, value, found := strings.Cut(item, ":"); found && strings.TrimSpace(key) == "type" {
				pluginType = strings.Trim(strings.TrimSpace(value), "\"'")
			}
			continue
		}
		if indent == 4 && strings.HasPrefix(trimmed, "type:") {
			pluginType = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "type:")), "\"'")
			continue
		}
		if !strings.HasPrefix(trimmed, "listen:") {
			continue
		}
		if pluginType != "udp_server" && pluginType != "tcp_server" {
			return errors.New("mosdns may bind DNS only through the expected UDP and TCP server plugins")
		}
		address := strings.Trim(strings.TrimSpace(strings.SplitN(strings.TrimPrefix(trimmed, "listen:"), "#", 2)[0]), "\"'")
		listenCounts[address]++
		if serverCounts[pluginType] == nil {
			serverCounts[pluginType] = map[string]int{}
		}
		serverCounts[pluginType][address]++
	}
	if sections["api"] != 1 || len(apiValues) != 1 || apiValues[0] != metrics {
		return errors.New("mosdns metrics API must bind exactly 127.0.0.1:15357")
	}
	if listenCounts[ordinary] != 2 || listenCounts[node] != 2 || len(listenCounts) != 2 ||
		serverCounts["udp_server"][ordinary] != 1 || serverCounts["udp_server"][node] != 1 ||
		serverCounts["tcp_server"][ordinary] != 1 || serverCounts["tcp_server"][node] != 1 ||
		len(serverCounts) != 2 {
		return errors.New("mosdns must bind exactly one UDP and one TCP listener on 127.0.0.1:15353 and :15354")
	}
	return nil
}

func validateCapturePolicy(policy string) error {
	for _, pattern := range []string{
		`(?i)\bchain\s+dns\s*\{`,
		`(?i)\bredirect\s+to\s*:53\b`,
		`(?i)\b(?:th\s+)?(?:dport|sport)\s+53\b`,
		`(?im)^[^#\n]*\b(?:ipv6|ip6)\b[^#\n]*\breject\b`,
	} {
		matched, err := regexp.MatchString(pattern, policy)
		if err != nil {
			return err
		}
		if matched {
			return errors.New("capture policy contains a forbidden LAN DNS/IPv6 exception")
		}
	}
	for _, line := range strings.Split(policy, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if regexp.MustCompile(`(?i)\breject\b`).MatchString(line) &&
			!regexp.MustCompile(`(?i)\bmeta\s+nfproto\s+ipv4\b`).MatchString(line) {
			return errors.New("capture policy reject must be explicitly scoped to IPv4")
		}
	}
	return nil
}

func validateCapturePolicyMode(policy, mode string) error {
	if err := validateCapturePolicy(policy); err != nil {
		return err
	}
	count := strings.Count(policy, "__SB_ROUTER_ADDRESSES__")
	if mode == cacheModeCTMark {
		if count != 2 {
			return errors.New("ctmark-v1 policy must contain exactly two router-address placeholders")
		}
		return validateCacheFastPathPolicy(policy)
	}
	if count != 0 {
		return errors.New("cache-off policy must not contain a router-address placeholder")
	}
	for _, line := range strings.Split(policy, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.Contains(line, "ct mark & 0x60000000 ==") || strings.Contains(line, "ct status &") {
			return errors.New("cache-off policy contains a connection-verdict fast path")
		}
	}
	return nil
}

const cacheDirectFastPathRule = "ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ } ct state { new, established } ct direction original ct status & 0x9 == 0x8 meta l4proto { tcp, udp } ct mark & 0x60000000 == 0x60000000 meta mark set (meta mark & 0x9fffffff) | 0x60000000 return"
const cacheProxyFastPathRule = "ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ } ct state { new, established } ct direction original ct status & 0x9 == 0x8 meta l4proto { tcp, udp } ct mark & 0x60000000 == 0x20000000 meta mark set (meta mark & 0x9fffffff) | 0x20000000 return"

func validateCacheFastPathPolicy(policy string) error {
	active := make([]string, 0)
	for _, raw := range strings.Split(policy, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line != "" {
			active = append(active, line)
		}
	}

	directCount, proxyCount := 0, 0
	indices := map[string]int{}
	for i, line := range active {
		switch line {
		case cacheDirectFastPathRule:
			directCount++
			indices[cacheDirectFastPathRule] = i
		case cacheProxyFastPathRule:
			proxyCount++
			indices[cacheProxyFastPathRule] = i
		default:
			if strings.Contains(line, "ct mark & 0x60000000 ==") || strings.Contains(line, "ct status &") {
				return errors.New("ctmark-v1 policy contains an unexpected connection-verdict fast-path rule")
			}
		}
	}
	if directCount != 1 || proxyCount != 1 {
		return errors.New("ctmark-v1 policy must contain one exact direct and proxy fast-path rule")
	}

	guards := []string{
		`iifname != "br-lan" return`,
		"meta nfproto != ipv4 return",
		"fib daddr type { local, broadcast, multicast } return",
		"ip daddr @lan_net return",
		"ct direction reply return",
	}
	classifyIndex, guardChainIndex := -1, -1
	for i, line := range active {
		if line == "chain classify {" {
			classifyIndex = i
		}
		if line == "chain guard {" && guardChainIndex < 0 {
			guardChainIndex = i
		}
	}
	if classifyIndex < 0 || guardChainIndex < 0 || classifyIndex > indices[cacheDirectFastPathRule] || guardChainIndex <= indices[cacheProxyFastPathRule] {
		return errors.New("ctmark-v1 fast path must remain inside the prerouting classifier")
	}
	previous := -1
	for _, guard := range guards {
		index := -1
		for i, line := range active {
			if line == guard {
				index = i
				break
			}
		}
		if index < 0 || index <= previous {
			return errors.New("ctmark-v1 fast path must follow the LAN, IPv4, local, and reply exclusions")
		}
		previous = index
	}
	if indices[cacheDirectFastPathRule] <= previous || indices[cacheProxyFastPathRule] <= previous {
		return errors.New("ctmark-v1 fast path must follow the LAN, IPv4, local, and reply exclusions")
	}
	return nil
}

func newDNSRejectMatcher(rules []dnsDomainRule) func(string) bool {
	full := make(map[string]bool)
	suffix := make(map[string]bool)
	var patterns []dnsDomainRule
	for _, rule := range rules {
		switch rule.kind {
		case "full":
			full[rule.name] = true
		case "domain":
			suffix[rule.name] = true
		case "regexp":
			patterns = append(patterns, rule)
		}
	}
	return func(name string) bool {
		if full[name] {
			return true
		}
		for tail := name; ; {
			if suffix[tail] {
				return true
			}
			dot := strings.IndexByte(tail, '.')
			if dot == -1 {
				break
			}
			tail = tail[dot+1:]
		}
		for _, rule := range patterns {
			if rule.matches(name) {
				return true
			}
		}
		return false
	}
}

func directProbeName(rules []dnsDomainRule, rejected func(string) bool) (string, bool) {
	for _, rule := range rules {
		switch rule.kind {
		case "full":
			if !rejected(rule.name) {
				return rule.name, true
			}
		case "domain":
			for _, candidate := range []string{"sing-box-health." + rule.name, rule.name, "codex-probe." + rule.name} {
				if validDNSName(candidate) && !rejected(candidate) {
					return candidate, true
				}
			}
		}
	}
	for _, rule := range rules {
		if rule.kind != "regexp" {
			continue
		}
		candidate, err := regexpProbe(rule.name)
		if err == nil && rule.matches(candidate) && !rejected(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func regexpProbe(expression string) (string, error) {
	parsed, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return "", err
	}
	sample, err := regexpSample(parsed)
	if err != nil {
		return "", err
	}
	for _, candidate := range []string{sample, "a" + sample, "health" + sample, sample + "a"} {
		candidate = strings.TrimSuffix(strings.ToLower(candidate), ".")
		if validDNSName(candidate) {
			compiled, compileErr := regexp.Compile(expression)
			if compileErr == nil && compiled.MatchString(candidate) {
				return candidate, nil
			}
		}
	}
	return "", errors.New("regexp has no simple DNS probe sample")
}

func regexpSample(expression *syntax.Regexp) (string, error) {
	switch expression.Op {
	case syntax.OpNoMatch:
		return "", errors.New("regexp cannot match")
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return "", nil
	case syntax.OpLiteral:
		return string(expression.Rune), nil
	case syntax.OpCharClass:
		for _, candidate := range "abcdefghijklmnopqrstuvwxyz0123456789-_" {
			for index := 0; index+1 < len(expression.Rune); index += 2 {
				if candidate >= expression.Rune[index] && candidate <= expression.Rune[index+1] {
					return string(candidate), nil
				}
			}
		}
		return "", errors.New("regexp character class has no DNS-label character")
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return "a", nil
	case syntax.OpCapture:
		return regexpSample(expression.Sub[0])
	case syntax.OpConcat:
		var builder strings.Builder
		for _, child := range expression.Sub {
			part, err := regexpSample(child)
			if err != nil {
				return "", err
			}
			builder.WriteString(part)
		}
		return builder.String(), nil
	case syntax.OpAlternate:
		if len(expression.Sub) == 0 {
			return "", errors.New("empty regexp alternative")
		}
		var lastErr error
		for _, alternative := range expression.Sub {
			candidate, err := regexpSample(alternative)
			if err == nil && candidate != "" {
				return candidate, nil
			}
			if err != nil {
				lastErr = err
			}
		}
		if lastErr != nil {
			return "", lastErr
		}
		return "", errors.New("regexp alternative produces an empty sample")
	case syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		if len(expression.Sub) == 0 {
			return "", errors.New("empty regexp repeat")
		}
		count := expression.Min
		if count == 0 {
			count = 1
		}
		if count > 8 {
			return "", errors.New("regexp probe repeat is too long")
		}
		part, err := regexpSample(expression.Sub[0])
		if err != nil {
			return "", err
		}
		return strings.Repeat(part, count), nil
	default:
		return "", fmt.Errorf("unsupported regexp operation %s", expression.Op)
	}
}

func reservedDNSProbeName(direct []dnsDomainRule, rejected func(string) bool) string {
	for _, candidate := range []string{
		"codex-probe.invalid", "codex-probe.example", "codex-probe.example.net",
		"codex-probe.test", "codex-probe.example.org", "codex-probe.example.com",
	} {
		if rejected(candidate) {
			continue
		}
		matched := false
		for _, rule := range direct {
			if rule.matches(candidate) {
				matched = true
				break
			}
		}
		if !matched {
			return candidate
		}
	}
	return ""
}

var dnsQueryID atomic.Uint32

func dnsMessage(name string) ([]byte, uint16, error) {
	name = strings.TrimSuffix(name, ".")
	if !validDNSName(name) {
		return nil, 0, errors.New("invalid DNS probe name")
	}
	id := uint16(dnsQueryID.Add(1))
	if id == 0 {
		id = uint16(dnsQueryID.Add(1))
	}
	query := make([]byte, 12, 12+len(name)+2+4)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query, id, nil
}

func dnsExchange(port int, name, network string) error {
	return dnsExchangeContext(context.Background(), port, name, network)
}

func dnsExchangeContext(parent context.Context, port int, name, network string) (result error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	defer func() {
		if err := ctx.Err(); err != nil {
			result = err
		} else if !time.Now().Before(deadline) {
			result = context.DeadlineExceeded
		}
	}()
	query, id, err := dnsMessage(name)
	if err != nil {
		return err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	if network == "tcp" {
		framed := make([]byte, 2, len(query)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		framed = append(framed, query...)
		if _, err = conn.Write(framed); err != nil {
			return err
		}
		var length [2]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint16(length[:])
		if size < 12 {
			return errors.New("short DNS-over-TCP response")
		}
		response := make([]byte, int(size))
		if _, err = io.ReadFull(conn, response); err != nil {
			return err
		}
		return validateDNSResponse(response, id, query)
	}
	if _, err = conn.Write(query); err != nil {
		return err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return err
	}
	return validateDNSResponse(response[:n], id, query)
}

func validateDNSResponse(response []byte, id uint16, query []byte) error {
	if len(response) < 12 || binary.BigEndian.Uint16(response[0:2]) != id || binary.BigEndian.Uint16(response[4:6]) != 1 {
		return errors.New("invalid DNS probe response")
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 {
		return errors.New("DNS probe received a non-response, unexpected opcode, or truncated packet")
	}
	code := flags & 0x000f
	if code != 0 && code != 3 {
		return fmt.Errorf("DNS probe returned RCODE %d", code)
	}
	name, offset, err := dnsWireName(response, 12)
	if err != nil {
		return err
	}
	want, queryEnd, err := dnsWireName(query, 12)
	if err != nil || queryEnd+4 != len(query) || offset+4 > len(response) ||
		!strings.EqualFold(name, want) || !bytes.Equal(response[offset:offset+4], query[queryEnd:]) {
		return errors.New("DNS probe question mismatch")
	}
	offset += 4
	count := int(binary.BigEndian.Uint16(response[6:8])) + int(binary.BigEndian.Uint16(response[8:10])) + int(binary.BigEndian.Uint16(response[10:12]))
	for index := 0; index < count; index++ {
		_, offset, err = dnsWireName(response, offset)
		if err != nil || offset+10 > len(response) {
			return errors.New("truncated DNS probe resource record")
		}
		length := int(binary.BigEndian.Uint16(response[offset+8 : offset+10]))
		offset += 10 + length
		if offset > len(response) {
			return errors.New("truncated DNS probe record data")
		}
	}
	if offset != len(response) {
		return errors.New("trailing DNS probe data")
	}
	return nil
}

// DNS compression can occur in questions and record names. Bound pointer walks
// and expanded names so malformed local responses cannot pass startup readiness.
func dnsWireName(data []byte, offset int) (string, int, error) {
	next := -1
	labels := []string{}
	seen := map[int]bool{}
	length := 1
	for {
		if offset < 0 || offset >= len(data) || seen[offset] {
			return "", 0, errors.New("invalid DNS probe name/pointer")
		}
		seen[offset] = true
		size := int(data[offset])
		if size&0xc0 == 0xc0 {
			if offset+2 > len(data) {
				return "", 0, errors.New("truncated DNS probe pointer")
			}
			if next < 0 {
				next = offset + 2
			}
			offset = (size&0x3f)<<8 | int(data[offset+1])
			continue
		}
		if size&0xc0 != 0 || offset+1+size > len(data) {
			return "", 0, errors.New("invalid DNS probe label")
		}
		offset++
		if size == 0 {
			if next < 0 {
				next = offset
			}
			return strings.Join(labels, "."), next, nil
		}
		length += size + 1
		if length > 255 {
			return "", 0, errors.New("oversized DNS probe name")
		}
		labels = append(labels, string(data[offset:offset+size]))
		offset += size
	}
}

type childExit struct {
	name string
	err  error
}

type managedChild struct {
	name   string
	pid    int
	done   <-chan struct{}
	result func() error
	stop   func() error
}

type lifecycleHooks struct {
	start          func(string) (*managedChild, error)
	ready          func(string) (bool, error)
	readyContext   func(context.Context, string) (bool, error)
	activate       func() error
	restore        func() error
	startupTimeout time.Duration
	retryInterval  time.Duration
}

func runLifecycle(ctx context.Context, hooks lifecycleHooks) (result error) {
	if hooks.startupTimeout <= 0 {
		hooks.startupTimeout = startupTimeout
	}
	if hooks.retryInterval <= 0 {
		hooks.retryInterval = startupRetry
	}
	exits := make(chan childExit, 4)
	children := []*managedChild{}
	start := func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		child, err := hooks.start(name)
		if err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
		if child == nil || child.done == nil || child.stop == nil || child.result == nil {
			return fmt.Errorf("start %s returned an incomplete child handle", name)
		}
		children = append(children, child)
		go func(current *managedChild) {
			<-current.done
			exits <- childExit{name: current.name, err: current.result()}
		}(child)
		return nil
	}
	waitReady := func(stage string) error {
		stageCtx, cancel := context.WithTimeout(ctx, hooks.startupTimeout)
		defer cancel()
		ticker := time.NewTicker(hooks.retryInterval)
		defer ticker.Stop()
		var last error
		for {
			select {
			case exit := <-exits:
				return unexpectedExit(exit, stage)
			case <-ctx.Done():
				return ctx.Err()
			case <-stageCtx.Done():
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if last != nil {
					return fmt.Errorf("%s readiness timed out: %w", stage, last)
				}
				return fmt.Errorf("%s readiness timed out", stage)
			case <-ticker.C:
				var ready bool
				var err error
				if hooks.readyContext != nil {
					ready, err = hooks.readyContext(stageCtx, stage)
				} else {
					ready, err = hooks.ready(stage)
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if stageCtx.Err() != nil {
					return fmt.Errorf("%s readiness timed out: %w", stage, stageCtx.Err())
				}
				if err != nil {
					last = err
				}
				if ready {
					return nil
				}
			}
		}
	}
	cleanup := func() error {
		var cleanupErr error
		for index := len(children) - 1; index >= 0; index-- {
			if err := children[index].stop(); err != nil {
				cleanupErr = appendError(cleanupErr, fmt.Errorf("stop %s: %w", children[index].name, err))
			}
		}
		if cleanupErr == nil && hooks.restore != nil {
			cleanupErr = hooks.restore()
		}
		return cleanupErr
	}
	defer func() {
		if errors.Is(result, context.Canceled) && ctx.Err() != nil {
			result = nil // An authorized stop is not an unexpected core failure.
		}
		if err := cleanup(); err != nil {
			result = appendError(result, fmt.Errorf("lifecycle cleanup: %w", err))
		}
	}()
	if hooks.start == nil || (hooks.ready == nil && hooks.readyContext == nil) || hooks.activate == nil || hooks.restore == nil {
		return errors.New("incomplete lifecycle hooks")
	}
	if err := start("mosdns"); err != nil {
		return err
	}
	if err := waitReady("mosdns-direct-node"); err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		}
		return err
	}
	if err := start("sing-box"); err != nil {
		return err
	}
	for _, stage := range []string{"sing-box-tun", "proxy-dns"} {
		if err := waitReady(stage); err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := hooks.activate(); err != nil {
		return fmt.Errorf("activate capture: %w", err)
	}
	select {
	case exit := <-exits:
		return unexpectedExit(exit, "active service")
	case <-ctx.Done():
		return nil
	}
}

func unexpectedExit(exit childExit, stage string) error {
	if exit.err == nil {
		return fmt.Errorf("%s exited unexpectedly during %s", exit.name, stage)
	}
	return fmt.Errorf("%s exited unexpectedly during %s: %w", exit.name, stage, exit.err)
}

func appendError(current, next error) error {
	if current == nil {
		return next
	}
	return fmt.Errorf("%v; %w", current, next)
}

func (c *controller) startCore(name string) (*managedChild, error) {
	pidPath := filepath.Join(c.state, name+".pid")
	if _, err := os.Lstat(pidPath); err == nil {
		return nil, fmt.Errorf("retained %s PID record requires review", name)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	var command *exec.Cmd
	switch name {
	case "mosdns":
		command = exec.Command(filepath.Join(c.root, "mosdns"), "start", "-c", "mosdns.yaml", "-d", c.root)
	case "sing-box":
		command = exec.Command(filepath.Join(c.root, "sing-box"), "-D", c.root, "run", "-c", filepath.Join(c.root, "config.json"))
	default:
		return nil, errors.New("unknown core")
	}
	command.Dir = c.root
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	if err := createPID(pidPath, command.Process.Pid); err != nil {
		killErr := command.Process.Kill()
		waitErr := command.Wait()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			err = appendError(err, fmt.Errorf("terminate unrecorded %s child: %w", name, killErr))
		}
		if waitErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				err = appendError(err, fmt.Errorf("reap unrecorded %s child: %w", name, waitErr))
			}
		}
		return nil, err
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = command.Wait()
		close(done)
	}()
	result := func() error {
		<-done
		return waitErr
	}
	stop := func() error {
		select {
		case <-done:
			return nil
		default:
		}
		if err := command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-timer.C:
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			killTimer := time.NewTimer(5 * time.Second)
			defer killTimer.Stop()
			select {
			case <-done:
				return nil
			case <-killTimer.C:
				return errors.New("child process did not exit after SIGKILL")
			}
		}
	}
	return &managedChild{name: name, pid: command.Process.Pid, done: done, result: result, stop: stop}, nil
}

func createPID(path string, pid int) error {
	if err := directory(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create owned PID record: %w", err)
	}
	if _, err = file.WriteString(strconv.Itoa(pid) + "\n"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			err = appendError(err, fmt.Errorf("remove incomplete PID record: %w", removeErr))
		}
		return err
	}
	return nil
}

func (c *controller) removeCorePID(name string, pid int) error {
	path := filepath.Join(c.state, name+".pid")
	if err := regular(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(data)) != strconv.Itoa(pid) {
		return fmt.Errorf("%s PID record changed; retained for review", name)
	}
	return os.Remove(path)
}

func (c *controller) lifecycleReady(stage string) (bool, error) {
	checkProcess := func(name string) error {
		if c.processCheck != nil {
			return c.processCheck(name)
		}
		if name == "mosdns" {
			return c.processRunning(name, filepath.Join(c.root, "mosdns"), []string{"start", "-c", "mosdns.yaml", "-d", c.root})
		}
		return c.processRunning(name, filepath.Join(c.root, "sing-box"), []string{"-D", c.root, "run", "-c", filepath.Join(c.root, "config.json")})
	}
	probeDNS := func(port int, name, network string) error {
		if c.dnsProbe != nil {
			return c.dnsProbe(port, name, network)
		}
		return dnsExchangeContext(c.commandContext, port, name, network)
	}
	switch stage {
	case "wan-network":
		data, err := c.command("ubus", "call", "network.interface.wan", "status")
		if err != nil {
			return false, err
		}
		value, err := decode(data)
		if err != nil {
			return false, err
		}
		wan := object(value)
		up, ok := wan["up"].(bool)
		if !ok || !up {
			return false, nil
		}
		device := text(wan["l3_device"])
		if !regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`).MatchString(device) {
			return false, errors.New("invalid WAN l3_device")
		}
		if _, err = c.command("ip", "link", "show", "dev", device); err != nil {
			return false, err
		}
		route, err := c.command("ip", "-4", "route", "show", "default", "dev", device)
		if err != nil {
			return false, err
		}
		lan, err := c.command("ip", "-4", "-o", "address", "show", "dev", "br-lan", "scope", "global")
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(string(route)) != "" && strings.TrimSpace(string(lan)) != "", nil
	case "mosdns-direct-node":
		if err := checkProcess("mosdns"); err != nil {
			return false, err
		}
		names, err := c.dnsProbeNames()
		if err != nil {
			return false, err
		}
		if names.haveDirect {
			for _, network := range []string{"udp", "tcp"} {
				if err = probeDNS(15353, names.direct, network); err != nil {
					return false, fmt.Errorf("mosdns direct DNS %s: %w", network, err)
				}
			}
		}
		if names.node == "" {
			return false, errors.New("no reserved node DNS probe name remains outside the reject domain rules")
		}
		for _, network := range []string{"udp", "tcp"} {
			if err = probeDNS(15354, names.node, network); err != nil {
				return false, fmt.Errorf("mosdns node DNS %s: %w", network, err)
			}
		}
		return true, nil
	case "sing-box-tun":
		if err := checkProcess("mosdns"); err != nil {
			return false, err
		}
		if err := checkProcess("sing-box"); err != nil {
			return false, err
		}
		if _, err := c.command("ip", "link", "show", "dev", "sb-tun"); err != nil {
			return false, err
		}
		return true, nil
	case "proxy-dns":
		if err := checkProcess("mosdns"); err != nil {
			return false, err
		}
		if err := checkProcess("sing-box"); err != nil {
			return false, err
		}
		names, err := c.dnsProbeNames()
		if err != nil {
			return false, err
		}
		if names.proxyErr != "" {
			return false, errors.New(names.proxyErr)
		}
		name := names.proxy
		for _, network := range []string{"udp", "tcp"} {
			if err = probeDNS(15353, name, network); err != nil {
				return false, fmt.Errorf("mosdns proxy DNS %s: %w", network, err)
			}
		}
		return true, nil
	default:
		return false, errors.New("unknown readiness stage")
	}
}

func (c *controller) waitStartupNetwork(ctx context.Context) error {
	timeout, retry := c.networkWait, c.networkRetry
	if timeout <= 0 {
		timeout = networkReadinessTimeout
	}
	if retry <= 0 {
		retry = networkReadinessRetry
	}
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(retry)
	defer ticker.Stop()
	var last error
	for {
		if err := stageCtx.Err(); err != nil {
			return fmt.Errorf("WAN network readiness timed out/canceled: %w", err)
		}
		ready, err := c.readinessContext(stageCtx, "wan-network")
		if contextErr := stageCtx.Err(); contextErr != nil {
			return fmt.Errorf("WAN network readiness timed out/canceled: %w", contextErr)
		}
		if err != nil {
			last = err
		} else if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stageCtx.Done():
			if last != nil {
				return fmt.Errorf("WAN network readiness timed out: %w", last)
			}
			return errors.New("WAN network readiness timed out")
		case <-ticker.C:
		}
	}
}

func (c *controller) recoverPriorBoot(boot string) (bool, error) {
	j, err := c.load()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if j.Boot == boot {
		if j.Phase != "restored" {
			return false, errors.New("incomplete same-boot lifecycle; explicit stop/review required")
		}
		return false, nil
	}
	if err = c.clearStaleCorePIDRecords(); err != nil {
		return false, err
	}
	if err = c.stop(); err != nil {
		return false, err
	}
	return true, nil
}

func (c *controller) startLifecycle(ctx context.Context) (cleanupComplete bool, result error) {
	boot, err := c.boot()
	if err != nil {
		return false, err
	}
	// The cache boot gate must run before stale-boot recovery: a changed or
	// same-boot package must not start a new lifecycle. If it fails, the only
	// permitted work is safe restoration of a valid prior-boot journal.
	c.cacheLifecycleAuthorized = true
	decision, err := c.checkCacheBoot()
	if err != nil {
		c.cacheRecoveryOnly = true
		recovered, recoveryErr := c.recoverPriorBoot(boot)
		if recoveryErr != nil {
			return recovered, appendError(err, fmt.Errorf("prior-boot recovery while cache startup is refused: %w", recoveryErr))
		}
		return recovered, err
	}
	if decision.Mode == cacheModeCTMark && decision.Boot != boot {
		return false, cacheGuardError("boot identity changed while checking cache startup")
	}
	c.cacheAuthorization = &decision
	// Restore a previous boot before config or WAN checks: its DNS bridge may
	// point at cores that no longer exist, and recovery must work offline.
	cleanupComplete, err = c.recoverPriorBoot(boot)
	if err != nil {
		return false, err
	}
	if err = c.withCommandContext(ctx, func() error {
		_, checkErr := c.runCommand("", filepath.Join(c.root, "sing-box"), "-D", c.root, "check", "-c", filepath.Join(c.root, "config.json"))
		return checkErr
	}); err != nil {
		return cleanupComplete, fmt.Errorf("sing-box configuration check: %w", err)
	}
	if err = c.waitStartupNetwork(ctx); err != nil {
		return cleanupComplete, err
	}
	if err = c.withCommandContext(ctx, c.prepare); err != nil {
		if j, loadErr := c.load(); loadErr == nil && j.Boot == boot && j.Phase != "restored" {
			if restoreErr := c.stop(); restoreErr != nil {
				cleanupComplete = false
				result = appendError(err, fmt.Errorf("partial startup restoration: %w", restoreErr))
				return cleanupComplete, result
			}
			cleanupComplete = true
		}
		return cleanupComplete, err
	}
	cleanupComplete = false
	var children []*managedChild
	restore := func() error {
		for index := len(children) - 1; index >= 0; index-- {
			if err := c.removeCorePID(children[index].name, children[index].pid); err != nil {
				return err
			}
		}
		if err := c.stop(); err != nil {
			return err
		}
		cleanupComplete = true
		return nil
	}
	start := func(name string) (*managedChild, error) {
		child, startErr := c.startCore(name)
		if startErr == nil {
			children = append(children, child)
		}
		return child, startErr
	}
	result = runLifecycle(ctx, lifecycleHooks{start: start, readyContext: c.readinessContext, activate: func() error {
		return c.withCommandContext(ctx, c.apply)
	}, restore: restore})
	return cleanupComplete, result
}

func (c *controller) supervisionState(cleanupComplete bool) string {
	if cleanupComplete {
		if j, err := c.load(); err == nil && j.Phase == "restored" && c.noOwnedObjects() == nil {
			return "restored"
		}
	}
	if _, err := c.load(); err == nil || !os.IsNotExist(err) {
		return "failed"
	}
	if c.noOwnedObjects() != nil {
		return "failed"
	}
	return "not-started"
}

func (c *controller) supervise(ctx context.Context) error {
	return c.superviseWith(func() (bool, error) {
		return c.startLifecycle(ctx)
	})
}

func (c *controller) superviseWith(start func() (bool, error)) (result error) {
	statusPath := filepath.Join(c.state, "restoration-status")
	exitPath := filepath.Join(c.state, "service-exit")
	for _, path := range []string{statusPath, exitPath} {
		if _, err := os.Lstat(path); err == nil {
			if err = regular(path); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(exitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := atomicWrite(statusPath, []byte("pending\n")); err != nil {
		return err
	}
	state := "not-started"
	cleanupComplete := false
	defer func() {
		if recovered := recover(); recovered != nil {
			result = appendError(result, fmt.Errorf("service supervisor panic: %v", recovered))
			state = "failed"
		} else {
			state = c.supervisionState(cleanupComplete)
		}
		if err := atomicWrite(statusPath, []byte(state+"\n")); err != nil {
			result = appendError(result, fmt.Errorf("write restoration status: %w", err))
			if state != "failed" {
				state = "failed"
				if fallbackErr := atomicWrite(statusPath, []byte("failed\n")); fallbackErr != nil {
					result = appendError(result, fmt.Errorf("write failed restoration status: %w", fallbackErr))
				}
			}
		}
		rc := "0\n"
		if result != nil {
			rc = "1\n"
		}
		if err := atomicWrite(exitPath, []byte(rc)); err != nil {
			result = appendError(result, fmt.Errorf("write service exit status: %w", err))
		}
	}()
	cleanupComplete, result = start()
	return result
}

func newSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}
