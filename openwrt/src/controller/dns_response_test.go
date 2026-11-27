package main

import (
	"encoding/binary"
	"testing"
)

func TestDNSReadinessRejectsMalformedOrUnrelatedResponses(t *testing.T) {
	query, id, err := dnsMessage("readiness.example")
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(base[2:4], 0x8180)
	for _, kind := range []string{"valid", "nxdomain", "answer", "short-question", "wrong-name", "wrong-type", "truncated", "opcode", "missing-record", "short-rdata", "pointer-loop", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			response := append([]byte(nil), base...)
			switch kind {
			case "nxdomain":
				response[3] |= 3
			case "answer", "short-rdata":
				binary.BigEndian.PutUint16(response[6:8], 1)
				response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
				if kind == "short-rdata" {
					response = response[:len(response)-1]
				}
			case "short-question":
				response = response[:12]
			case "wrong-name":
				response[13] = 'x'
			case "wrong-type":
				response[len(response)-3] = 28
			case "truncated":
				response[2] |= 2
			case "opcode":
				response[2] |= 8
			case "missing-record":
				binary.BigEndian.PutUint16(response[6:8], 1)
			case "pointer-loop":
				response = append(response[:12], 0xc0, 12, 0, 1, 0, 1)
			case "trailing":
				response = append(response, 0)
			}
			err := validateDNSResponse(response, id, query)
			valid := kind == "valid" || kind == "nxdomain" || kind == "answer"
			if (err == nil) != valid {
				t.Fatalf("valid=%v, got error %v", valid, err)
			}
		})
	}
}
