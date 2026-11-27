package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

var benchmarkDigest [32]byte
var benchmarkRules []dnsDomainRule
var benchmarkProbeNames dnsProbeNames

func benchmarkInput(b *testing.B, variable string) string {
	b.Helper()
	path := os.Getenv(variable)
	if path == "" {
		b.Skip(variable + " is not set")
	}
	if _, err := os.Stat(path); err != nil {
		b.Fatal(err)
	}
	return path
}

func BenchmarkParseProductionDomainRules(b *testing.B) {
	path := benchmarkInput(b, "SB_DOMAIN_FIXTURE")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rules, parseErr := parseDNSDomainRules(data)
		if parseErr != nil || len(rules) != 113832 {
			b.Fatalf("rules=%d error=%v", len(rules), parseErr)
		}
		benchmarkRules = rules
	}
}

func BenchmarkDNSProbeNamesColdProduction(b *testing.B) {
	path := benchmarkInput(b, "SB_DOMAIN_FIXTURE")
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		controller := &controller{root: filepath.Dir(path)}
		names, loadErr := controller.dnsProbeNames()
		if loadErr != nil {
			b.Fatal(loadErr)
		}
		benchmarkProbeNames = names
	}
}

func BenchmarkDNSProbeNamesWarmProduction(b *testing.B) {
	path := benchmarkInput(b, "SB_DOMAIN_FIXTURE")
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	controller := &controller{root: filepath.Dir(path)}
	want, err := controller.dnsProbeNames()
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		got, loadErr := controller.dnsProbeNames()
		if loadErr != nil || got != want {
			b.Fatalf("names=%+v error=%v", got, loadErr)
		}
		benchmarkProbeNames = got
	}
}

func BenchmarkWholeFileCoreSHA256(b *testing.B) {
	path := benchmarkInput(b, "SB_CORE_FIXTURE")
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			b.Fatal(readErr)
		}
		benchmarkDigest = sha256.Sum256(data)
	}
}

func BenchmarkStreamingCoreSHA256(b *testing.B) {
	path := benchmarkInput(b, "SB_CORE_FIXTURE")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	expected := sha256.Sum256(data)
	length := len(data)
	data = nil
	buffer := make([]byte, payloadHashBufferSize)
	b.SetBytes(int64(length))
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		digest, hashErr := hashRegularFile(path, buffer)
		if hashErr != nil {
			b.Fatal(hashErr)
		}
		if digest != expected {
			b.Fatal("streamed digest differs from whole-file SHA256")
		}
		benchmarkDigest = digest
	}
}
