package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWANRejectsReadyResultAfterDeadline(t *testing.T) {
	c := &controller{networkWait: 10 * time.Millisecond}
	c.readyCheck = func(string) (bool, error) {
		if c.commandContext == nil {
			t.Fatal("WAN check did not inherit its stage deadline")
		}
		<-c.commandContext.Done()
		return true, nil
	}
	err := c.waitStartupNetwork(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || c.commandContext != nil {
		t.Fatalf("late success accepted or context retained: %v", err)
	}
}

func TestLifecycleRejectsLateReadinessAndRestoresWithFreshContext(t *testing.T) {
	c := &controller{}
	c.readyCheck = func(string) (bool, error) {
		<-c.commandContext.Done()
		return true, nil
	}
	done := make(chan struct{})
	var once sync.Once
	stopped, restored, activated := false, false, false
	err := runLifecycle(context.Background(), lifecycleHooks{
		start: func(string) (*managedChild, error) {
			return &managedChild{name: "mosdns", done: done, result: func() error { return nil }, stop: func() error {
				stopped = true
				once.Do(func() { close(done) })
				return nil
			}}, nil
		},
		readyContext: c.readinessContext,
		activate:     func() error { activated = true; return nil },
		restore: func() error {
			if c.commandContext != nil {
				t.Fatal("restoration inherited expired startup context")
			}
			restored = true
			return nil
		},
		startupTimeout: 15 * time.Millisecond,
		retryInterval:  time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) || !stopped || !restored || activated {
		t.Fatalf("late readiness lifecycle result: err=%v stopped=%t restored=%t activated=%t", err, stopped, restored, activated)
	}
}

func TestDNSProbeUsesFiveSecondBudgetAndParentCancellation(t *testing.T) {
	if probeTimeout != 5*time.Second {
		t.Fatalf("DNS budget %s does not match mosdns upstream budget", probeTimeout)
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = dnsExchangeContext(ctx, port, "deadline.example", "udp")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("DNS ignored parent deadline: %v duration=%s port=%s", err, time.Since(start), strconv.Itoa(port))
	}
}

func TestCanceledApplyAfterDNSCommitRestoresOwnedStateWithoutRetry(t *testing.T) {
	f := newFixture(t)
	baseline := f.dns
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := f.c.run
	committed := false
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		output, err := base(input, command, args...)
		if !committed && err == nil && command == "uci" && strings.Contains(input, "commit dhcp") {
			committed = true
			cancel() // State changed before the caller learns the operation failed.
			return nil, context.Canceled
		}
		return output, err
	}
	err := f.c.withCommandContext(ctx, f.c.apply)
	if !errors.Is(err, context.Canceled) || !committed || !reflect.DeepEqual(f.dns, bridgeDNS()) {
		t.Fatalf("did not inject uncertain committed DNS mutation: err=%v dns=%#v", err, f.dns)
	}
	if f.c.commandContext != nil {
		t.Fatal("canceled startup context leaked into recovery")
	}
	if err := f.c.stop(); err != nil {
		t.Fatalf("fresh-context restoration failed: %v", err)
	}
	if !reflect.DeepEqual(f.dns, baseline) || f.include || f.table || f.extraDHCP != "150" {
		t.Fatalf("owned-only restoration failed: dns=%#v include=%t table=%t extra=%s", f.dns, f.include, f.table, f.extraDHCP)
	}
	j, err := f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("restoration journal: %#v %v", j, err)
	}
}

func TestTimedOutNFTStagingReleasesHoldAndRetainsUnrecordedRules(t *testing.T) {
	f := newFixture(t)
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	base := f.c.run
	injected := false
	f.c.run = func(input, command string, args ...string) ([]byte, error) {
		output, err := base(input, command, args...)
		if !injected && err == nil && command == "nft" && strings.Join(args, " ") == "-f -" && strings.Contains(input, "table inet sb_proxy") {
			injected = true
			return nil, context.DeadlineExceeded
		}
		return output, err
	}
	if err := f.c.apply(); !errors.Is(err, context.DeadlineExceeded) || !injected {
		t.Fatalf("NFT timeout not injected: %v", err)
	}
	if err := f.c.stop(); err == nil || !strings.Contains(err.Error(), "startup hold released") {
		t.Fatalf("unrecorded NFT must be preserved after restoring native routing: %v", err)
	}
	if !f.table || !f.dormant || len(f.routes["-4/10073"]) != 0 || f.include || reflect.DeepEqual(f.dns, bridgeDNS()) {
		t.Fatal("uncertain staging lost its inert table or changed LAN routing/DNS")
	}
	j, err := f.c.load()
	if err != nil || j.Phase == "restored" {
		t.Fatalf("uncertain transaction falsely reported restored: %#v %v", j, err)
	}
}
