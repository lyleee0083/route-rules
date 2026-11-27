package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRouteSnapshotSelectsOnlyRequestedTable(t *testing.T) {
	payload := `[
{"dst":"default","dev":"wan","metric":10},
{"table":"main","dst":"default","dev":"wan2"},
{"table":254,"dst":"192.168.0.0/16","dev":"br-lan"},
{"table":"local","type":"local","dst":"127.0.0.1","dev":"lo"},
{"table":"default","dst":"default","dev":"foreign"},
{"table":"prelocal","dst":"10.0.0.0/8","dev":"other"},
{"table":220,"dst":"10.1.0.0/16","dev":"ipsec0"},
{"table":10073,"type":"unreachable","dst":"default","metric":42760},
{"table":"10074","dst":"default","dev":"sb-tun","metric":10}
]`
	calls := 0
	c := &controller{run: func(input, command string, args ...string) ([]byte, error) {
		if input != "" || command != "ip" || strings.Join(args, " ") != "-4 -j route show table all" {
			t.Fatalf("unexpected query: %s %v", command, args)
		}
		calls++
		return []byte(payload), nil
	}}
	for table, want := range map[string]int{"10073": 1, "10074": 1, "main": 3, "254": 3, "10076": 0} {
		data, err := c.routes("-4", table)
		if err != nil {
			t.Fatal(err)
		}
		value, err := decode(data)
		if err != nil || len(list(value)) != want {
			t.Fatalf("table=%s want=%d data=%s err=%v", table, want, data, err)
		}
		if want == 0 && string(data) != "[]" {
			t.Fatalf("missing table is not an empty array: %s", data)
		}
	}
	if calls != 5 {
		t.Fatalf("unexpected query count: %d", calls)
	}
}

func fullRouteSnapshotCalls(calls []string) int {
	count := 0
	for _, call := range calls {
		if call == "ip -4 -j route show table all" {
			count++
		}
	}
	return count
}

func TestRoutingScopeUsesOneFullRouteSnapshot(t *testing.T) {
	f := newFixture(t)
	if err := f.c.routing(false); err != nil {
		t.Fatal(err)
	}
	if count := fullRouteSnapshotCalls(f.calls); count != 1 {
		t.Fatalf("read-only routing scope used %d full route snapshots, want 1: %v", count, f.calls)
	}
}

func TestInstallRoutingRefreshesSnapshotAfterRouteMutation(t *testing.T) {
	f := newFixture(t)
	if err := f.c.installRouting(false); err != nil {
		t.Fatal(err)
	}
	if count := fullRouteSnapshotCalls(f.calls); count != 3 {
		t.Fatalf("routing scope plus two route ownership checks used %d full snapshots, want 3: %v", count, f.calls)
	}
	for _, spec := range routeSpecs {
		if spec.hold {
			continue
		}
		found := false
		for _, entry := range f.routes[spec.family+"/"+spec.table] {
			if routeMatches(object(entry), spec) {
				found = true
			}
		}
		if !found {
			t.Fatalf("route was not installed after a fresh snapshot: %+v", spec)
		}
	}
}

func TestRouteSnapshotNeverSwallowsErrorsOrAmbiguousData(t *testing.T) {
	cases := []struct {
		name, payload string
		err           error
	}{
		{"dump terminated", "[", errors.New("exit status 2: Dump terminated")},
		{"old missing-table message", "[", errors.New("FIB table does not exist")},
		{"permission denied", "", errors.New("Operation not permitted")},
		{"truncated json", "[", nil},
		{"wrong shape", `{}`, nil},
		{"null entry", `[null]`, nil},
		{"null table", `[{"table":null}]`, nil},
		{"empty alias", `[{"table":""}]`, nil},
		{"unknown alias", `[{"table":"user_alias"}]`, nil},
		{"fractional table", `[{"table":10073.5}]`, nil},
		{"negative table", `[{"table":-1}]`, nil},
		{"overflow table", `[{"table":4294967296}]`, nil},
		{"object table", `[{"table":{}}]`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &controller{run: func(string, string, ...string) ([]byte, error) { return []byte(tc.payload), tc.err }}
			if _, err := c.routes("-4", "10073"); err == nil {
				t.Fatal("invalid or failed snapshot accepted as an empty project table")
			}
		})
	}
}

func TestRouteSnapshotLifecycleOnFreshQWRT(t *testing.T) {
	f := newFixture(t)
	// These are unrelated live routes, including a default with the same
	// metric as the project's TUN route. They must never satisfy ownership.
	f.routes["-4/main"] = []any{map[string]any{"dst": "default", "dev": "wan", "metric": 10}}
	f.routes["-4/220"] = []any{map[string]any{"dst": "10.0.0.0/8", "dev": "ipsec0"}}
	originalRoutes := encoded(f.routes)
	originalDNS := f.dns
	// Reproduce the exact missing-table failure; production must not call it.
	for _, table := range []string{"10073", "10074"} {
		data, err := f.run("", "ip", "-4", "-j", "route", "show", "table", table)
		if err == nil || string(data) != "[" {
			t.Fatalf("fixture does not reproduce target empty-table error: %s %v", data, err)
		}
	}
	f.calls = nil
	if _, err := f.c.preflight(); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal("preflight mutated state")
	}
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.apply(); err != nil {
		t.Fatal(err)
	}
	writes := len(f.writes)
	f.calls = nil
	if err := f.c.inspect(); err != nil {
		t.Fatal(err)
	}
	if count := fullRouteSnapshotCalls(f.calls); count != 2 {
		t.Fatalf("inspect should refresh scope and presence phases independently while reusing within each phase; got %d full snapshots: %v", count, f.calls)
	}
	if len(f.writes) != writes {
		t.Fatal("inspect mutated state")
	}
	if err := f.c.stop(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"10073", "10074"} {
		if len(f.routes["-4/"+table]) != 0 {
			t.Fatalf("project route table remains: %s", table)
		}
		delete(f.routes, "-4/"+table)
	}
	for _, rules := range f.rules {
		if len(rules) != 0 {
			t.Fatal("project policy rule or startup hold remains")
		}
	}
	if string(encoded(f.routes)) != string(originalRoutes) || !reflect.DeepEqual(f.dns, originalDNS) || f.table || f.include {
		t.Fatal("stop did not preserve unrelated routes or restore owned integration")
	}
	j, err := f.c.load()
	if err != nil || j.Phase != "restored" {
		t.Fatalf("restoration not complete: %+v %v", j, err)
	}
	// Restart preparation must work after both project tables become empty.
	if err := f.c.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.stop(); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "ip -4 -j route show table ") && call != "ip -4 -j route show table all" {
			t.Fatalf("unsafe per-table query reintroduced: %s", call)
		}
	}
}

func TestRouteSnapshotForeignReservedTableStillBlocksWithoutWrites(t *testing.T) {
	for _, table := range []string{"10073", "10074"} {
		t.Run(table, func(t *testing.T) {
			f := newFixture(t)
			f.routes["-4/"+table] = []any{map[string]any{"dst": "10.0.0.0/8", "dev": "user0"}}
			if _, err := f.c.preflight(); err == nil {
				t.Fatal("foreign route in reserved table was hidden by snapshot filtering")
			}
			if len(f.writes) != 0 {
				t.Fatal("collision check mutated state")
			}
		})
	}
}
