package mosdnstest

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type responsePlan struct {
	rcode           int
	answer          bool
	ttl             uint32
	delay           time.Duration
	silent          bool
	wholeMessageTTL bool
}

type dohAction struct {
	dns        responsePlan
	httpStatus int
	timeout    bool
}

type upstream struct {
	conn     *net.UDPConn
	count    atomic.Int32
	byNameMu sync.Mutex
	byName   map[string]int
	reply    func(string) responsePlan
}

func successfulAnswer(ttl uint32) responsePlan {
	return responsePlan{answer: true, ttl: ttl}
}

func parseQuestion(request []byte) (string, int, error) {
	if len(request) < 17 {
		return "", 0, fmt.Errorf("short DNS question")
	}
	offset := 12
	labels := make([]string, 0, 4)
	for {
		if offset >= len(request) {
			return "", 0, fmt.Errorf("unterminated DNS question")
		}
		length := int(request[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(request) {
			return "", 0, fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, string(request[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(request) {
		return "", 0, fmt.Errorf("truncated DNS question type")
	}
	return strings.ToLower(strings.Join(labels, ".")), offset + 4, nil
}

func makeDNSResponse(request []byte, questionEnd int, plan responsePlan) []byte {
	response := append([]byte(nil), request[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], uint16(0x8180|plan.rcode))
	binary.BigEndian.PutUint16(response[6:8], 0)
	if plan.answer && plan.rcode == 0 {
		ttl := plan.ttl
		if ttl == 0 {
			ttl = 5
		}
		if plan.wholeMessageTTL {
			binary.BigEndian.PutUint16(response[6:8], 2)
			binary.BigEndian.PutUint16(response[10:12], 1)
			// The CNAME starts at QNAME and has TTL=0. Its target is an
			// uncompressed alias.test name followed by an A record.
			cnameTarget := []byte{5, 'a', 'l', 'i', 'a', 's', 4, 't', 'e', 's', 't', 0}
			cname := []byte{0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 0, 0, byte(len(cnameTarget))}
			cname = append(cname, cnameTarget...)
			targetOffset := len(response) + len(cname) - len(cnameTarget)
			response = append(response, cname...)
			aRecord := make([]byte, 12)
			binary.BigEndian.PutUint16(aRecord[0:2], uint16(0xc000|targetOffset))
			binary.BigEndian.PutUint16(aRecord[2:4], 1)
			binary.BigEndian.PutUint16(aRecord[4:6], 1)
			binary.BigEndian.PutUint32(aRecord[6:10], ttl)
			binary.BigEndian.PutUint16(aRecord[10:12], 4)
			response = append(response, aRecord...)
			response = append(response, 192, 0, 2, 10)
			// OPT's TTL field contains flags and must not be rewritten.
			response = append(response, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0)
			return response
		}
		binary.BigEndian.PutUint16(response[6:8], 1)
		// Pointer to QNAME, IN A, and 192.0.2.10. Different TTLs identify
		// which local mock won a fallback race without changing production TTLs.
		answer := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 10}
		binary.BigEndian.PutUint32(answer[6:10], ttl)
		response = append(response, answer...)
	}
	return response
}

func startUpstream(t *testing.T, reply func(string) responsePlan) *upstream {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{conn: conn, byName: make(map[string]int), reply: reply}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			request := append([]byte(nil), buffer[:n]...)
			name, questionEnd, parseErr := parseQuestion(request)
			if parseErr != nil {
				continue
			}
			u.count.Add(1)
			u.byNameMu.Lock()
			u.byName[name]++
			u.byNameMu.Unlock()
			plan := u.reply(name)
			if plan.silent {
				continue
			}
			go func(request []byte, questionEnd int, addr *net.UDPAddr, plan responsePlan) {
				if plan.delay > 0 {
					time.Sleep(plan.delay)
				}
				_, _ = conn.WriteToUDP(makeDNSResponse(request, questionEnd, plan), addr)
			}(request, questionEnd, addr, plan)
		}
	}()
	return u
}

func (u *upstream) requestsFor(name string) int {
	u.byNameMu.Lock()
	defer u.byNameMu.Unlock()
	return u.byName[name]
}

type dohMock struct {
	mu      sync.Mutex
	byName  map[string]int
	request atomic.Int32
}

func (d *dohMock) requestsFor(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.byName[name]
}

func decodeDoHRequest(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, fmt.Errorf("GET request has no dns parameter")
		}
		return base64.RawURLEncoding.DecodeString(encoded)
	}
	return io.ReadAll(r.Body)
}

func planDoHResponse(name string) responsePlan {
	switch name {
	case "servfail-direct.test":
		return responsePlan{rcode: 2}
	case "refused-direct.test":
		return responsePlan{rcode: 5}
	case "notimp-direct.test":
		return responsePlan{rcode: 4}
	case "both-failed-direct.test":
		return responsePlan{rcode: 2}
	case "negative-direct.test":
		return responsePlan{rcode: 3}
	case "nodata-direct.test":
		return responsePlan{rcode: 0}
	case "slow-primary-backup-error-direct.test":
		return responsePlan{answer: true, ttl: 5, delay: 1200 * time.Millisecond}
	case "slow-primary-hedge-direct.test":
		return responsePlan{answer: true, ttl: 5, delay: 1500 * time.Millisecond}
	default:
		if strings.Contains(name, "negative") {
			return responsePlan{rcode: 3}
		}
		return successfulAnswer(5)
	}
}

func startDoHMock(t *testing.T, plan func(string) dohAction) (*httptest.Server, *dohMock) {
	t.Helper()
	mock := &dohMock{byName: make(map[string]int)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := decodeDoHRequest(r)
		if err != nil {
			http.Error(w, "invalid local DNS fixture request", http.StatusBadRequest)
			return
		}
		name, questionEnd, err := parseQuestion(request)
		if err != nil {
			http.Error(w, "invalid local DNS fixture question", http.StatusBadRequest)
			return
		}
		mock.request.Add(1)
		mock.mu.Lock()
		mock.byName[name]++
		mock.mu.Unlock()
		action := plan(name)
		if action.httpStatus != 0 {
			w.WriteHeader(action.httpStatus)
			return
		}
		if action.timeout {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Second):
				return
			}
		}
		if action.dns.delay > 0 {
			timer := time.NewTimer(action.dns.delay)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return
			case <-timer.C:
			}
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(makeDNSResponse(request, questionEnd, action.dns))
	}))
	t.Cleanup(server.Close)
	return server, mock
}

func startDoHPrimary(t *testing.T) (*httptest.Server, *dohMock) {
	t.Helper()
	return startDoHMock(t, func(name string) dohAction {
		switch name {
		case "node-primary-http429.test":
			return dohAction{httpStatus: http.StatusTooManyRequests}
		case "node-primary-timeout.test":
			return dohAction{timeout: true}
		case "node-primary-servfail.test", "node-both-failed.test":
			return dohAction{dns: responsePlan{rcode: 2}}
		case "node-primary-refused.test":
			return dohAction{dns: responsePlan{rcode: 5}}
		case "node-primary-slow-backup-error.test":
			return dohAction{dns: responsePlan{answer: true, ttl: 5, delay: 1200 * time.Millisecond}}
		case "negative-node.test":
			return dohAction{dns: responsePlan{rcode: 3}}
		case "nodata-node.test":
			return dohAction{dns: responsePlan{rcode: 0}}
		case "node-whole-message-ttl.test":
			return dohAction{dns: responsePlan{answer: true, ttl: 5, wholeMessageTTL: true}}
		}
		if name == "http429-direct.test" {
			return dohAction{httpStatus: http.StatusTooManyRequests}
		}
		if name == "timeout-direct.test" {
			return dohAction{timeout: true}
		}
		return dohAction{dns: planDoHResponse(name)}
	})
}

func replaceForward(t *testing.T, yaml, tag, upstreamTag string, u *upstream) string {
	t.Helper()
	return replaceForwardBlock(t, yaml, tag, fmt.Sprintf("tag: %s\naddr: udp://%s", upstreamTag, u.conn.LocalAddr()))
}

func replaceForwardDoH(t *testing.T, yaml, tag, upstreamTag, address string) string {
	t.Helper()
	return replaceForwardBlock(t, yaml, tag, fmt.Sprintf("tag: %s\naddr: %s\ninsecure_skip_verify: true", upstreamTag, address))
}

func replaceForwardBlock(t *testing.T, yaml, tag, upstreamConfig string) string {
	t.Helper()
	start := strings.Index(yaml, "  - tag: "+tag+"\n")
	if start < 0 {
		t.Fatalf("missing forward %s", tag)
	}
	relativeEnd := strings.Index(yaml[start+1:], "\n  - tag: ")
	if relativeEnd < 0 {
		t.Fatalf("unterminated forward block %s", tag)
	}
	end := start + 1 + relativeEnd + 1
	lines := strings.Split(strings.TrimSpace(upstreamConfig), "\n")
	if len(lines) < 2 {
		t.Fatal("invalid local forward fixture")
	}
	replacement := fmt.Sprintf("  - tag: %s\n    type: forward\n    args:\n      concurrent: 1\n      upstreams:\n        - %s\n", tag, strings.TrimSpace(lines[0]))
	for _, line := range lines[1:] {
		replacement += "          " + strings.TrimSpace(line) + "\n"
	}
	return yaml[:start] + replacement + yaml[end:]
}

func privatePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	u, err := net.ListenPacket("udp4", address)
	if err != nil {
		_ = l.Close()
		t.Fatal(err)
	}
	_ = u.Close()
	_ = l.Close()
	return address
}

type dnsResourceRecord struct {
	typeCode uint16
	ttl      uint32
}

type dnsResponseSections struct {
	rcode      int
	answers    []dnsResourceRecord
	authority  []dnsResourceRecord
	additional []dnsResourceRecord
}

func skipDNSName(packet []byte, offset int) (int, error) {
	for {
		if offset >= len(packet) {
			return 0, fmt.Errorf("truncated DNS name")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			return offset, nil
		}
		if length&0xc0 == 0xc0 {
			if offset >= len(packet) {
				return 0, fmt.Errorf("truncated DNS compression pointer")
			}
			return offset + 1, nil
		}
		if length > 63 || offset+length > len(packet) {
			return 0, fmt.Errorf("invalid DNS label")
		}
		offset += length
	}
}

func parseDNSResponse(packet []byte) (dnsResponseSections, error) {
	if len(packet) < 12 {
		return dnsResponseSections{}, fmt.Errorf("short DNS response")
	}
	sections := dnsResponseSections{rcode: int(packet[3] & 15)}
	offset := 12
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	for i := 0; i < questionCount; i++ {
		var err error
		offset, err = skipDNSName(packet, offset)
		if err != nil || offset+4 > len(packet) {
			return dnsResponseSections{}, fmt.Errorf("invalid DNS question")
		}
		offset += 4
	}
	counts := []int{
		int(binary.BigEndian.Uint16(packet[6:8])),
		int(binary.BigEndian.Uint16(packet[8:10])),
		int(binary.BigEndian.Uint16(packet[10:12])),
	}
	sectionsByIndex := []*[]dnsResourceRecord{&sections.answers, &sections.authority, &sections.additional}
	for sectionIndex, count := range counts {
		for i := 0; i < count; i++ {
			var err error
			offset, err = skipDNSName(packet, offset)
			if err != nil || offset+10 > len(packet) {
				return dnsResponseSections{}, fmt.Errorf("invalid DNS resource record")
			}
			record := dnsResourceRecord{
				typeCode: binary.BigEndian.Uint16(packet[offset : offset+2]),
				ttl:      binary.BigEndian.Uint32(packet[offset+4 : offset+8]),
			}
			dataLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
			offset += 10
			if offset+dataLength > len(packet) {
				return dnsResponseSections{}, fmt.Errorf("truncated DNS resource data")
			}
			*sectionsByIndex[sectionIndex] = append(*sectionsByIndex[sectionIndex], record)
			offset += dataLength
		}
	}
	return sections, nil
}

func buildDNSQuery(name string, qtype uint16) []byte {
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request[0:2], 0x4321)
	binary.BigEndian.PutUint16(request[2:4], 0x0100)
	binary.BigEndian.PutUint16(request[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		request = append(request, byte(len(label)))
		request = append(request, label...)
	}
	request = append(request, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return request
}

func buildDNSQueryWithEDNS(name string, qtype uint16) []byte {
	request := buildDNSQuery(name, qtype)
	binary.BigEndian.PutUint16(request[10:12], 1)
	// Advertise a 1232 byte UDP payload and set the DNSSEC OK bit.
	return append(request, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0)
}

func queryRawWithTimeout(t *testing.T, address, name string, qtype uint16, network string, timeout time.Duration) ([]byte, time.Duration) {
	t.Helper()
	return queryRawPacketWithTimeout(t, address, name, buildDNSQuery(name, qtype), network, timeout)
}

func queryRawWithEDNSTimeout(t *testing.T, address, name string, qtype uint16, network string, timeout time.Duration) ([]byte, time.Duration) {
	t.Helper()
	return queryRawPacketWithTimeout(t, address, name, buildDNSQueryWithEDNS(name, qtype), network, timeout)
}

func queryRawPacketWithTimeout(t *testing.T, address, name string, request []byte, network string, timeout time.Duration) ([]byte, time.Duration) {
	t.Helper()
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	started := time.Now()
	_ = conn.SetDeadline(started.Add(timeout))
	var response []byte
	if strings.HasPrefix(network, "tcp") {
		framed := make([]byte, len(request)+2)
		binary.BigEndian.PutUint16(framed[:2], uint16(len(request)))
		copy(framed[2:], request)
		if _, err = io.Copy(conn, bytes.NewReader(framed)); err != nil {
			t.Fatalf("DNS TCP query %s write failed: %v", name, err)
		}
		lengthPrefix := make([]byte, 2)
		if _, err = io.ReadFull(conn, lengthPrefix); err != nil {
			t.Fatalf("DNS TCP query %s timed out after %s: %v", name, time.Since(started), err)
		}
		length := int(binary.BigEndian.Uint16(lengthPrefix))
		if length < 12 || length > 4096 {
			t.Fatalf("invalid DNS TCP response length: %d", length)
		}
		response = make([]byte, length)
		if _, err = io.ReadFull(conn, response); err != nil {
			t.Fatalf("DNS TCP query %s response was truncated: %v", name, err)
		}
	} else {
		if _, err = conn.Write(request); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, readErr := conn.Read(buffer)
		if readErr != nil {
			t.Fatalf("DNS query %s timed out after %s: %v", name, time.Since(started), readErr)
		}
		response = append([]byte(nil), buffer[:n]...)
	}
	if len(response) < 12 || binary.BigEndian.Uint16(response[:2]) != 0x4321 {
		t.Fatal("invalid DNS response")
	}
	return response, time.Since(started)
}

func queryWithNetworkTimeout(t *testing.T, address, name string, qtype uint16, network string, timeout time.Duration) (int, uint32, time.Duration) {
	response, elapsed := queryRawWithTimeout(t, address, name, qtype, network, timeout)
	sections, err := parseDNSResponse(response)
	if err != nil {
		t.Fatalf("invalid DNS response for %s: %v", name, err)
	}
	if len(sections.answers) == 0 {
		return sections.rcode, 0, elapsed
	}
	return sections.rcode, sections.answers[0].ttl, elapsed
}

func queryWithTimeout(t *testing.T, address, name string, qtype uint16, timeout time.Duration) (int, uint32, time.Duration) {
	return queryWithNetworkTimeout(t, address, name, qtype, "udp4", timeout)
}

func queryTCPWithTimeout(t *testing.T, address, name string, qtype uint16, timeout time.Duration) (int, uint32, time.Duration) {
	return queryWithNetworkTimeout(t, address, name, qtype, "tcp4", timeout)
}

func query(t *testing.T, address, name string, qtype uint16) (int, uint32) {
	t.Helper()
	rcode, ttl, _ := queryWithTimeout(t, address, name, qtype, 2*time.Second)
	return rcode, ttl
}

func readMetrics(t *testing.T, address string) string {
	t.Helper()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatalf("local metrics API request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("local metrics API status = %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestOfficialMosdnsPolicyBehavior(t *testing.T) {
	binaryPath := os.Getenv("MOSDNS_CHECK_EXE")
	packagePath := os.Getenv("MOSDNS_PACKAGE_ZIP")
	if binaryPath == "" || packagePath == "" {
		t.Skip("set MOSDNS_CHECK_EXE and MOSDNS_PACKAGE_ZIP for isolated official-core acceptance")
	}
	archive, err := zip.OpenReader(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	var yaml string
	var rejectData []byte
	for _, file := range archive.File {
		switch file.Name {
		case "mosdns.yaml", "dns-reject-domains.txt":
			r, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			closeErr := r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if file.Name == "mosdns.yaml" {
				yaml = string(data)
			} else {
				rejectData = data
			}
		}
	}
	assertBlocked := func(address, name string, qtype uint16) {
		t.Helper()
		for _, network := range []string{"udp4", "tcp4"} {
			response, _ := queryRawWithTimeout(t, address, name, qtype, network, 2*time.Second)
			sections, err := parseDNSResponse(response)
			if err != nil || sections.rcode != 5 || len(sections.answers) != 0 {
				t.Fatalf("blocked %s type %d via %s %s: RCODE=%d answers=%d err=%v",
					name, qtype, address, network, sections.rcode, len(sections.answers), err)
			}
		}
	}
	hasRejectPolicy := strings.Contains(yaml, "qname $reject_domains")
	if hasRejectPolicy != (len(rejectData) > 0) {
		t.Fatal("package must provide a nonempty reject list when its DNS policy uses it")
	}
	if yaml == "" || !strings.Contains(yaml, "http: 127.0.0.1:15357") {
		t.Fatal("package has no MosDNS policy with the loopback-only metrics API")
	}
	if strings.Contains(yaml, "0.0.0.0:15357") || strings.Contains(yaml, "[::]:15357") {
		t.Fatal("package metrics API is not loopback-only")
	}
	ordinaryAddress, nodeAddress, apiAddress := privatePort(t), privatePort(t), privatePort(t)
	if ordinaryAddress == nodeAddress || ordinaryAddress == apiAddress || nodeAddress == apiAddress {
		t.Fatal("duplicate isolated DNS or API test ports")
	}
	aliHTTP, aliHTTPMock := startDoHPrimary(t)
	tencent := startUpstream(t, func(name string) responsePlan {
		switch name {
		case "slow-primary-backup-error-direct.test", "node-primary-slow-backup-error.test":
			return responsePlan{rcode: 5}
		case "both-failed-direct.test", "node-both-failed.test":
			return responsePlan{rcode: 2}
		default:
			return successfulAnswer(7)
		}
	})
	cloudflare := startUpstream(t, func(name string) responsePlan {
		switch name {
		case "proxy-both-failed.test":
			return responsePlan{rcode: 2}
		case "proxy-servfail.test":
			return responsePlan{rcode: 2}
		case "proxy-refused.test":
			return responsePlan{rcode: 5}
		case "negative-proxy.test":
			return responsePlan{rcode: 3}
		case "nodata-proxy.test":
			return responsePlan{rcode: 0}
		case "proxy-slow-backup-error.test":
			return responsePlan{answer: true, ttl: 5, delay: 2500 * time.Millisecond}
		case "proxy-hedge.test":
			return responsePlan{answer: true, ttl: 5, delay: 2500 * time.Millisecond}
		default:
			return successfulAnswer(5)
		}
	})
	google := startUpstream(t, func(name string) responsePlan {
		switch name {
		case "proxy-slow-backup-error.test":
			return responsePlan{rcode: 5}
		case "proxy-both-failed.test":
			return responsePlan{rcode: 2}
		default:
			return successfulAnswer(9)
		}
	})
	yaml = replaceForwardDoH(t, yaml, "direct_ali_forward", "ali_direct", aliHTTP.URL+"/dns-query")
	yaml = replaceForward(t, yaml, "direct_tencent_forward", "tencent_direct", tencent)
	yaml = replaceForward(t, yaml, "proxy_cloudflare_forward", "cloudflare_proxy", cloudflare)
	yaml = replaceForward(t, yaml, "proxy_google_forward", "google_proxy", google)
	yaml = strings.ReplaceAll(yaml, "127.0.0.1:15353", ordinaryAddress)
	yaml = strings.ReplaceAll(yaml, "127.0.0.1:15354", nodeAddress)
	yaml = strings.ReplaceAll(yaml, "127.0.0.1:15357", apiAddress)
	// Only the dedicated expiry QNAME receives a short test-only override. All other
	// node cases execute the packaged production ttl 3600 action unchanged.
	ttl3600AcceptBlock := "        exec: ttl 3600\n      - matches: has_resp\n        exec: accept\n  - tag: ordinary_udp"
	ttlExpiryOverride := "        exec: ttl 3600\n      - matches:\n          - qname node-expired.test\n          - qtype 1\n          - rcode 0\n          - resp_ip 0.0.0.0/0\n        exec: ttl 2\n      - matches: has_resp\n        exec: accept\n  - tag: ordinary_udp"
	if strings.Count(yaml, ttl3600AcceptBlock) != 1 {
		t.Fatal("could not isolate the node-expiry-only short TTL fixture")
	}
	yaml = strings.Replace(yaml, ttl3600AcceptBlock, ttlExpiryOverride, 1)
	for _, external := range []string{"doh.pub", "dns.alidns.com", "dns.google", "cloudflare-dns.com", "120.53.53.53", "223.5.5.5", "8.8.8.8", "1.1.1.1"} {
		if strings.Contains(yaml, external) {
			t.Fatalf("fixture config retained an external upstream endpoint: %s", external)
		}
	}
	if strings.Contains(yaml, "socks5:") {
		t.Fatal("fixture config retained a SOCKS proxy endpoint instead of local mocks")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "mosdns.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	directDomains := []string{
		"full:direct-unit.test",
		"domain:direct-suffix.test",
		"regexp:^regex[0-9]+\\.unit\\.test$",
		"full:servfail-direct.test",
		"full:refused-direct.test",
		"full:notimp-direct.test",
		"full:http429-direct.test",
		"full:timeout-direct.test",
		"full:slow-primary-backup-error-direct.test",
		"full:slow-primary-hedge-direct.test",
		"full:negative-direct.test",
		"full:nodata-direct.test",
		"full:both-failed-direct.test",
	}
	if hasRejectPolicy {
		// Include names that would otherwise use both ordinary and node upstreams.
		directDomains = append(directDomains, "full:blocked-direct.test")
		rejectData = append(rejectData, []byte("\nfull:blocked-direct.test\ndomain:blocked-suffix.test\n")...)
		if err := os.WriteFile(filepath.Join(directory, "dns-reject-domains.txt"), rejectData, 0600); err != nil {
			t.Fatal(err)
		}
	}
	domains := strings.Join(directDomains, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(directory, "dns-direct-domains.txt"), []byte(domains), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binaryPath, "start", "-c", "mosdns.yaml", "-d", directory)
	command.Dir = directory
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp4", ordinaryAddress, 50*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated MosDNS DNS listener did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	metricsReady := false
	for time.Now().Before(deadline) {
		client := &http.Client{Timeout: 300 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
		response, requestErr := client.Get("http://" + apiAddress + "/metrics")
		if requestErr == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && bytes.Contains(body, []byte("mosdns_")) {
				metricsReady = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !metricsReady {
		t.Fatal("isolated loopback /metrics endpoint did not become ready")
	}
	for _, name := range []string{"direct-unit.test", "sub.direct-suffix.test", "regex42.unit.test"} {
		if code, ttl := query(t, ordinaryAddress, name, 1); code != 0 || ttl != 5 {
			t.Fatalf("ordinary direct %s returned rcode=%d ttl=%d", name, code, ttl)
		}
	}
	if hasRejectPolicy {
		for _, name := range []string{"blocked-direct.test", "child.blocked-suffix.test"} {
			for _, address := range []string{ordinaryAddress, nodeAddress} {
				for _, qtype := range []uint16{1, 16, 28} {
					assertBlocked(address, name, qtype)
				}
			}
			if aliHTTPMock.requestsFor(name)+tencent.requestsFor(name)+cloudflare.requestsFor(name)+google.requestsFor(name) != 0 {
				t.Fatalf("rejected query %s reached an upstream", name)
			}
		}
	}

	if aliHTTPMock.requestsFor("direct-unit.test") != 1 || tencent.requestsFor("direct-unit.test") != 0 || cloudflare.requestsFor("direct-unit.test") != 0 {
		t.Fatal("normal Ali primary response did not avoid both backup and proxy DNS")
	}
	if code, ttl := query(t, ordinaryAddress, "unmatched-unit.test", 1); code != 0 || ttl != 5 {
		t.Fatal("default Cloudflare response or upstream TTL changed")
	}
	query(t, ordinaryAddress, "unmatched-unit.test", 1)
	if cloudflare.requestsFor("unmatched-unit.test") != 1 || google.requestsFor("unmatched-unit.test") != 0 {
		t.Fatal("normal Cloudflare primary or ordinary cache selection changed")
	}
	for _, address := range []string{ordinaryAddress, nodeAddress} {
		assertBlocked(address, "ipv6-unit.test", 28)
	}
	if aliHTTPMock.requestsFor("ipv6-unit.test")+tencent.requestsFor("ipv6-unit.test")+cloudflare.requestsFor("ipv6-unit.test")+google.requestsFor("ipv6-unit.test") != 0 {
		t.Fatal("blocked AAAA reached an upstream")
	}
	if code, ttl := query(t, nodeAddress, "node-unit.test", 1); code != 0 || ttl != 3600 {
		t.Fatalf("node result rcode=%d ttl=%d", code, ttl)
	}
	time.Sleep(1100 * time.Millisecond)
	if code, ttl, _ := queryTCPWithTimeout(t, nodeAddress, "node-unit.test", 1, 2*time.Second); code != 0 || ttl >= 3600 || ttl < 3597 {
		t.Fatalf("node cache TTL was renewed instead of counted down: %d", ttl)
	}
	if aliHTTPMock.requestsFor("node-unit.test") != 1 || tencent.requestsFor("node-unit.test") != 0 || cloudflare.requestsFor("node-unit.test") != 0 || google.requestsFor("node-unit.test") != 0 {
		t.Fatal("node cache miss did not use the shared ordinary direct fallback outside the direct-domain set")
	}
	if code, ttl := query(t, nodeAddress, "node-expired.test", 1); code != 0 || ttl != 2 {
		t.Fatalf("node expiry fixture initial answer rcode=%d ttl=%d", code, ttl)
	}
	time.Sleep(2300 * time.Millisecond)
	if code, ttl := query(t, nodeAddress, "node-expired.test", 1); code != 0 || ttl != 2 || aliHTTPMock.requestsFor("node-expired.test") != 2 {
		t.Fatalf("expired node cache entry was reused instead of refetched: rcode=%d ttl=%d upstream_requests=%d", code, ttl, aliHTTPMock.requestsFor("node-expired.test"))
	}
	if code, ttl := query(t, nodeAddress, "negative-node.test", 1); code != 3 || ttl != 0 || tencent.requestsFor("negative-node.test") != 0 {
		t.Fatal("valid node NXDOMAIN was rewritten or triggered the shared direct fallback")
	}
	if code, ttl := query(t, nodeAddress, "nodata-node.test", 1); code != 0 || ttl != 0 || tencent.requestsFor("nodata-node.test") != 0 {
		t.Fatal("valid node NOERROR/NODATA was rewritten or triggered the shared direct fallback")
	}
	wholeMessage, _ := queryRawWithEDNSTimeout(t, nodeAddress, "node-whole-message-ttl.test", 1, "udp4", 2*time.Second)
	wholeSections, err := parseDNSResponse(wholeMessage)
	if err != nil || wholeSections.rcode != 0 || len(wholeSections.answers) != 2 ||
		wholeSections.answers[0].typeCode != 5 || wholeSections.answers[0].ttl != 3600 ||
		wholeSections.answers[1].typeCode != 1 || wholeSections.answers[1].ttl != 3600 ||
		len(wholeSections.additional) != 1 || wholeSections.additional[0].typeCode != 41 || wholeSections.additional[0].ttl != 0x00008000 {
		t.Fatalf("node TTL did not rewrite all non-OPT answer records while preserving OPT: %#v err=%v", wholeSections, err)
	}
	time.Sleep(1100 * time.Millisecond)
	wholeMessageCacheHit, _ := queryRawWithEDNSTimeout(t, nodeAddress, "node-whole-message-ttl.test", 1, "tcp4", 2*time.Second)
	wholeHitSections, err := parseDNSResponse(wholeMessageCacheHit)
	if err != nil || wholeHitSections.rcode != 0 || len(wholeHitSections.answers) != 2 ||
		wholeHitSections.answers[0].typeCode != 5 || wholeHitSections.answers[0].ttl >= 3600 || wholeHitSections.answers[0].ttl < 3597 ||
		wholeHitSections.answers[1].typeCode != 1 || wholeHitSections.answers[1].ttl >= 3600 || wholeHitSections.answers[1].ttl < 3597 ||
		len(wholeHitSections.additional) != 1 || wholeHitSections.additional[0].typeCode != 41 || wholeHitSections.additional[0].ttl != 0x00008000 ||
		aliHTTPMock.requestsFor("node-whole-message-ttl.test") != 1 || tencent.requestsFor("node-whole-message-ttl.test") != 0 {
		t.Fatalf("whole-message production TTL cache hit did not count down across CNAME/A while preserving OPT and avoiding upstream: %#v err=%v", wholeHitSections, err)
	}

	for _, name := range []string{"node-primary-http429.test", "node-primary-timeout.test", "node-primary-servfail.test", "node-primary-refused.test"} {
		if code, ttl, elapsed := queryWithTimeout(t, nodeAddress, name, 1, 3*time.Second); code != 0 || ttl != 3600 || elapsed >= 1800*time.Millisecond {
			t.Fatalf("node shared direct fallback did not use the Tencent backup promptly for %s: rcode=%d ttl=%d elapsed=%s", name, code, ttl, elapsed)
		}
		// The core can retry a transport exchange. The contract here is a successful
		// fallback through both direct providers within the preceding deadline.
		if ali, backup := aliHTTPMock.requestsFor(name), tencent.requestsFor(name); ali == 0 || backup == 0 {
			t.Fatalf("node direct failure %s missed a provider: Ali=%d Tencent=%d", name, ali, backup)
		}
		if cloudflare.requestsFor(name) != 0 || google.requestsFor(name) != 0 {
			t.Fatalf("node direct failure %s escaped to proxy DNS", name)
		}
	}
	if code, ttl, elapsed := queryWithTimeout(t, nodeAddress, "node-primary-slow-backup-error.test", 1, 3*time.Second); code != 0 || ttl != 3600 || elapsed < time.Second {
		t.Fatalf("failed Tencent response overrode the slow healthy Ali node primary: rcode=%d ttl=%d elapsed=%s", code, ttl, elapsed)
	}
	if aliHTTPMock.requestsFor("node-primary-slow-backup-error.test") != 1 || tencent.requestsFor("node-primary-slow-backup-error.test") != 1 {
		t.Fatal("slow healthy node primary fixture did not execute the shared direct branches")
	}
	if code, _ := query(t, nodeAddress, "node-both-failed.test", 1); code != 2 {
		t.Fatalf("both shared direct providers returned rcode=%d, want bounded SERVFAIL", code)
	}
	if aliHTTPMock.requestsFor("node-both-failed.test") != 1 || tencent.requestsFor("node-both-failed.test") != 1 {
		t.Fatal("both failed node fixture did not exercise both shared direct providers")
	}

	if code, ttl := query(t, nodeAddress, "node-cache-isolated.test", 1); code != 0 || ttl != 3600 {
		t.Fatal("node cache isolation fixture did not obtain a node response")
	}
	if code, ttl := query(t, ordinaryAddress, "node-cache-isolated.test", 1); code != 0 || ttl != 5 {
		t.Fatal("ordinary DNS reused a node-only cached response")
	}
	query(t, ordinaryAddress, "node-cache-isolated.test", 1)
	if aliHTTPMock.requestsFor("node-cache-isolated.test") != 1 || cloudflare.requestsFor("node-cache-isolated.test") != 1 || google.requestsFor("node-cache-isolated.test") != 0 {
		t.Fatal("node and ordinary cache entries or provider paths were not independent")
	}
	if code, ttl := query(t, ordinaryAddress, "ordinary-cache-isolated.test", 1); code != 0 || ttl != 5 {
		t.Fatal("ordinary cache isolation fixture did not obtain an ordinary response")
	}
	query(t, ordinaryAddress, "ordinary-cache-isolated.test", 1)
	if code, ttl := query(t, nodeAddress, "ordinary-cache-isolated.test", 1); code != 0 || ttl != 3600 {
		t.Fatal("node DNS reused an ordinary-cache response")
	}
	query(t, nodeAddress, "ordinary-cache-isolated.test", 1)
	if cloudflare.requestsFor("ordinary-cache-isolated.test") != 1 || aliHTTPMock.requestsFor("ordinary-cache-isolated.test") != 1 || tencent.requestsFor("ordinary-cache-isolated.test") != 0 {
		t.Fatal("ordinary_cache was shared with node_cache or node cache hit queried an upstream")
	}

	for _, test := range []struct {
		name string
		code int
	}{
		{name: "servfail-direct.test", code: 2},
		{name: "refused-direct.test", code: 5},
		{name: "notimp-direct.test", code: 4},
	} {
		if code, ttl := query(t, ordinaryAddress, test.name, 1); code != 0 || ttl != 7 {
			t.Fatalf("direct retryable RCODE %s returned rcode=%d ttl=%d", test.name, code, ttl)
		}
		if aliHTTPMock.requestsFor(test.name) != 1 || tencent.requestsFor(test.name) != 1 {
			t.Fatalf("direct RCODE %d did not invoke Tencent backup exactly once", test.code)
		}
		if cloudflare.requestsFor(test.name) != 0 || google.requestsFor(test.name) != 0 {
			t.Fatalf("direct RCODE case %s crossed into proxy DNS", test.name)
		}
	}
	if code, ttl := query(t, ordinaryAddress, "http429-direct.test", 1); code != 0 || ttl != 7 {
		t.Fatalf("HTTP 429 from the direct primary did not fail over: rcode=%d ttl=%d", code, ttl)
	}
	if ali, backup := aliHTTPMock.requestsFor("http429-direct.test"), tencent.requestsFor("http429-direct.test"); ali == 0 || backup == 0 {
		t.Fatalf("HTTP 429 fixture missed a direct provider: Ali=%d Tencent=%d", ali, backup)
	}
	if cloudflare.requestsFor("http429-direct.test") != 0 || google.requestsFor("http429-direct.test") != 0 {
		t.Fatal("HTTP 429 direct fixture crossed into proxy DNS")
	}
	if code, ttl, elapsed := queryWithTimeout(t, ordinaryAddress, "timeout-direct.test", 1, 2*time.Second); code != 0 || ttl != 7 || elapsed >= 1700*time.Millisecond {
		t.Fatalf("direct timeout fallback was not bounded near the 300ms threshold: rcode=%d ttl=%d elapsed=%s", code, ttl, elapsed)
	}
	if code, ttl := query(t, ordinaryAddress, "slow-primary-backup-error-direct.test", 1); code != 0 || ttl != 5 {
		t.Fatalf("retryable Tencent backup response overrode a later valid Ali response: rcode=%d ttl=%d", code, ttl)
	}
	if tencent.requestsFor("slow-primary-backup-error-direct.test") != 1 {
		t.Fatal("slow-primary/backup-error fixture did not execute both direct branches")
	}
	if code, ttl, _ := queryWithTimeout(t, ordinaryAddress, "slow-primary-hedge-direct.test", 1, 3*time.Second); code != 0 || ttl != 7 {
		t.Fatalf("direct hedged backup did not win when the healthy primary exceeded 300ms: rcode=%d ttl=%d", code, ttl)
	}
	if code, _ := query(t, ordinaryAddress, "negative-direct.test", 1); code != 3 || tencent.requestsFor("negative-direct.test") != 0 {
		t.Fatal("valid direct NXDOMAIN incorrectly triggered Tencent fallback")
	}
	if code, ttl := query(t, ordinaryAddress, "nodata-direct.test", 1); code != 0 || ttl != 0 || tencent.requestsFor("nodata-direct.test") != 0 {
		t.Fatal("valid direct NOERROR/NODATA incorrectly triggered Tencent fallback")
	}
	if code, _ := query(t, ordinaryAddress, "both-failed-direct.test", 1); code != 2 {
		t.Fatalf("concurrent direct SERVFAIL/REFUSED failures returned rcode=%d, want bounded SERVFAIL", code)
	}
	if aliHTTPMock.requestsFor("both-failed-direct.test") != 1 || tencent.requestsFor("both-failed-direct.test") != 1 || cloudflare.requestsFor("both-failed-direct.test") != 0 || google.requestsFor("both-failed-direct.test") != 0 {
		t.Fatal("both-failed direct fixture did not fail on the two direct providers only")
	}

	for _, name := range []string{"proxy-servfail.test", "proxy-refused.test"} {
		if code, ttl := query(t, ordinaryAddress, name, 1); code != 0 || ttl != 9 {
			t.Fatalf("proxy retryable RCODE %s returned rcode=%d ttl=%d", name, code, ttl)
		}
		if google.requestsFor(name) != 1 {
			t.Fatalf("proxy retryable RCODE %s did not invoke Google backup", name)
		}
		if aliHTTPMock.requestsFor(name) != 0 || tencent.requestsFor(name) != 0 {
			t.Fatalf("proxy retryable RCODE %s crossed into direct DNS", name)
		}
	}
	if code, ttl := query(t, ordinaryAddress, "negative-proxy.test", 1); code != 3 || ttl != 0 || google.requestsFor("negative-proxy.test") != 0 {
		t.Fatal("valid proxy NXDOMAIN incorrectly triggered Google fallback")
	}
	if code, ttl := query(t, ordinaryAddress, "nodata-proxy.test", 1); code != 0 || ttl != 0 || google.requestsFor("nodata-proxy.test") != 0 {
		t.Fatal("valid proxy NOERROR/NODATA incorrectly triggered Google fallback")
	}
	if code, ttl, elapsed := queryWithTimeout(t, ordinaryAddress, "proxy-slow-backup-error.test", 1, 4*time.Second); code != 0 || ttl != 5 || elapsed < 2*time.Second {
		t.Fatalf("retryable Google backup response overrode a later valid Cloudflare response or primary timing was unexpected: rcode=%d ttl=%d elapsed=%s", code, ttl, elapsed)
	}
	if code, ttl, elapsed := queryWithTimeout(t, ordinaryAddress, "proxy-hedge.test", 1, 4*time.Second); code != 0 || ttl != 9 || elapsed >= 2400*time.Millisecond {
		t.Fatalf("proxy hedge did not use Google after the 2000ms threshold: rcode=%d ttl=%d elapsed=%s", code, ttl, elapsed)
	}
	if code, _ := query(t, ordinaryAddress, "proxy-both-failed.test", 1); code != 2 {
		t.Fatalf("concurrent proxy failures returned rcode=%d, want bounded SERVFAIL", code)
	}

	metrics := readMetrics(t, apiAddress)
	for _, metric := range []string{
		"mosdns_cache_query_total{tag=\"ordinary_cache\"}",
		"mosdns_cache_hit_total{tag=\"ordinary_cache\"}",
		"mosdns_forward_query_total",
		"mosdns_forward_err_total",
		"mosdns_metrics_collector_query_total{name=\"ordinary_dns\"}",
		"mosdns_metrics_collector_response_latency_millisecond_bucket{name=\"ordinary_dns\"",
		"mosdns_metrics_collector_query_total{name=\"node_dns\"}",
		"mosdns_metrics_collector_query_total{name=\"direct_ali_primary\"}",
		"mosdns_metrics_collector_query_total{name=\"direct_tencent_backup\"}",
	} {
		if !strings.Contains(metrics, metric) {
			t.Fatalf("loopback /metrics omitted expected cache/forward/request series %q", metric)
		}
	}
	if !strings.Contains(metrics, `upstream="ali_direct"`) || !strings.Contains(metrics, `upstream="tencent_direct"`) || !strings.Contains(metrics, `upstream="cloudflare_proxy"`) || !strings.Contains(metrics, `upstream="google_proxy"`) {
		t.Fatal("forward metrics do not identify the four shared direct and proxy provider tags")
	}
	if !strings.Contains(metrics, `tag="direct_ali_forward"`) || !strings.Contains(metrics, `tag="direct_tencent_forward"`) || !strings.Contains(metrics, `tag="proxy_cloudflare_forward"`) || !strings.Contains(metrics, `tag="proxy_google_forward"`) || strings.Contains(metrics, `node_ali_forward`) || strings.Contains(metrics, `node_tencent_forward`) {
		t.Fatal("forward metrics do not identify exactly the shared four ordinary provider plugin tags")
	}
	t.Log("official mosdns: node cache misses reuse the shared ordinary Ali/Tencent direct fallback, Cloudflare/Google proxy fallback, local HTTP 429, DNS error RCODES, transport timeout, valid NXDOMAIN/NODATA preservation, slow-primary/backup-error filtering, independent cache/expiry, whole-message TTL/OPT, UDP/TCP node entry, AAAA rejection, and loopback metrics all used local fixtures")
}
