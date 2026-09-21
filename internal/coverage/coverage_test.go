package coverage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"adama/event"
	"adama/sdk"
	natsserver "github.com/nats-io/nats-server/v2/server"
)

func bus(t *testing.T) *sdk.Bus {
	b, _ := busAt(t)
	return b
}

func busAt(t *testing.T) (*sdk.Bus, string) {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{JetStream: true, StoreDir: t.TempDir(), Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	t.Cleanup(s.Shutdown)
	b, err := sdk.Connect(context.Background(), s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b, s.ClientURL()
}

func publish(t *testing.T, b *sdk.Bus, ev event.Event) event.Event {
	t.Helper()
	if ev.Meta == nil {
		ev.Meta = map[string]string{}
	}
	if ev.RunID == "" {
		ev.RunID = "run1"
	}
	var err error
	ev, err = ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func record(t *testing.T, b *sdk.Bus, tool sdk.Definition, ev event.Event, status string, emitted int) {
	t.Helper()
	key := sdk.WorkKey(tool.Config(), ev)
	raw, _ := json.Marshal(sdk.Task{Key: key, Tool: tool.Name, Input: ev.AsInput(), RunID: ev.RunID, Status: status, Attempts: 3, Emitted: emitted})
	if _, err := b.KV.Put(context.Background(), key, raw); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, b *sdk.Bus, tools []sdk.Definition, run string) Report {
	t.Helper()
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		tool.Version = sdk.DefinitionVersion
		if _, err := b.Register(context.Background(), tool, false); err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	if err := b.SetInventory(context.Background(), names, true); err != nil {
		t.Fatal(err)
	}
	r, err := Snapshot(context.Background(), b, Filter{Run: run})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAbsentWorkerAndEachBackendRemainVisible(t *testing.T) {
	b := bus(t)
	tool := sdk.Definition{Name: "httpx", Kinds: []event.Kind{event.KindURL}}
	a := publish(t, b, event.Event{ID: "a", Kind: event.KindURL, Value: "https://app.example.com:8443/Admin", Target: event.Target{Host: "192.0.2.1"}})
	x := a
	x.ID, x.Host = "b", "192.0.2.2"
	x = publish(t, b, x)
	dup := a
	dup.ID = "duplicate"
	publish(t, b, dup)
	r := snapshot(t, b, []sdk.Definition{tool}, "run1")
	if len(r.Items) != 2 || r.Counts["unclaimed"] != 2 || r.Complete || r.Workers[0].ConsumerExists {
		t.Fatalf("lost offline work: %+v", r)
	}
	record(t, b, tool, a, sdk.TaskFailed, 0)
	record(t, b, tool, x, sdk.TaskCompleted, 1)
	r = snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Counts[sdk.TaskFailed] != 1 || r.Counts[sdk.TaskCompleted] != 1 || r.Complete {
		t.Fatalf("failure disappeared: %+v", r)
	}
	entry, err := b.KV.Get(context.Background(), sdk.WorkKey(tool.Config(), a))
	if err != nil {
		t.Fatal(err)
	}
	var task sdk.Task
	json.Unmarshal(entry.Value(), &task)
	if task.Attempts != 3 || task.Status != sdk.TaskFailed {
		t.Fatal("coverage modified terminal work")
	}
}

func TestLivenessPrerequisiteBothArrivalOrders(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		b := bus(t)
		tool := sdk.Definition{Name: "nmap-full", Kinds: []event.Kind{event.KindIP}, NeedLive: true}
		seed := event.Event{ID: "seed", Kind: event.KindIP, Value: "192.0.2.1"}
		live := seed
		live.ID, live.Meta = "live", event.MarkLive(nil)
		if reverse {
			live = publish(t, b, live)
			publish(t, b, seed)
		} else {
			publish(t, b, seed)
			r := snapshot(t, b, []sdk.Definition{tool}, "run1")
			if r.Counts["blocked_liveness"] != 1 {
				t.Fatalf("missing prerequisite: %+v", r)
			}
			live = publish(t, b, live)
		}
		record(t, b, tool, live, sdk.TaskCompleted, 0) // A successful scan may have no open ports.
		r := snapshot(t, b, []sdk.Definition{tool}, "run1")
		if !r.Complete || len(r.Items) != 1 {
			t.Fatalf("arrival order left stale blockers: %+v", r)
		}
	}
}

func TestNameResolutionRequiresAllBoundAddressesLive(t *testing.T) {
	b := bus(t)
	tool := sdk.Definition{Name: "nmap-quick", Kinds: []event.Kind{event.KindFQDN}, NeedLive: true}
	publish(t, b, event.Event{ID: "seed", Kind: event.KindDomain, Value: "example.com"})
	r := snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Counts["blocked_resolution"] != 1 {
		t.Fatalf("missing apex not visible: %+v", r)
	}
	for i, host := range []string{"192.0.2.1", "2001:db8::1"} {
		ev := event.Event{ID: []string{"a", "aaaa"}[i], Kind: event.KindFQDN, Value: "example.com", Target: event.Target{Name: "example.com", NameRole: event.NameDNSA, Host: host}}
		publish(t, b, ev)
		if i == 0 {
			ev.ID, ev.NameRole, ev.Meta = "live", event.NameRequested, event.MarkLive(nil)
			ev = publish(t, b, ev)
			record(t, b, tool, ev, sdk.TaskCompleted, 1)
		}
	}
	r = snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Counts["blocked_resolution"] != 0 || r.Counts["blocked_liveness"] != 1 || r.Counts[sdk.TaskCompleted] != 1 || r.Complete {
		t.Fatalf("lost unprobed backend: %+v", r)
	}
}

func TestScopeReuseIncludesEarlierDownstreamWork(t *testing.T) {
	b := bus(t)
	scan := sdk.Definition{Name: "scan", Kinds: []event.Kind{event.KindIP}}
	shot := sdk.Definition{Name: "httpx", Kinds: []event.Kind{event.KindURL}}
	seed := publish(t, b, event.Event{ID: "first", Kind: event.KindIP, Value: "192.0.2.1", Meta: map[string]string{"scope": "shared"}})
	record(t, b, scan, seed, sdk.TaskCompleted, 1)
	publish(t, b, event.Event{ID: "url", Kind: event.KindURL, Value: "http://192.0.2.1", Meta: map[string]string{"scope": "shared"}})
	seed.ID, seed.RunID = "second", "run2"
	publish(t, b, seed)
	r := snapshot(t, b, []sdk.Definition{scan, shot}, "run2")
	if r.Complete || r.Counts["unclaimed"] != 1 || r.Counts[sdk.TaskCompleted] != 1 || r.MatchedEvents != 3 {
		t.Fatalf("reused work omitted children: %+v", r)
	}
}

func TestDiscoveryOnlyStillNeedsResolution(t *testing.T) {
	b := bus(t)
	tool := sdk.Definition{Name: "nmap-discover", Kinds: []event.Kind{event.KindFQDN}, Filter: sdk.Not(sdk.FieldIn("alive", "true")), NeedBinding: true}
	publish(t, b, event.Event{ID: "name", Kind: event.KindFQDN, Value: "example.com"})
	r := snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Complete || r.Counts["blocked_resolution"] != 1 {
		t.Fatalf("discovery dependency disappeared: %+v", r)
	}
	publish(t, b, event.Event{ID: "resolved", Kind: event.KindFQDN, Value: "example.com", Target: event.Target{Host: "192.0.2.1", Name: "example.com", NameRole: event.NameDNSA}})
	r = snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Counts["blocked_resolution"] != 0 || r.Counts["unclaimed"] != 1 {
		t.Fatalf("resolution did not unblock discovery: %+v", r)
	}
}

func TestMissingEvidenceRetentionAndGatesCannotCertifyCoverage(t *testing.T) {
	b := bus(t)
	tool := sdk.Definition{Name: "resolve", Kinds: []event.Kind{event.KindFQDN}, Evidence: "DNS address binding"}
	ev := publish(t, b, event.Event{ID: "name", Kind: event.KindFQDN, Value: "example.com"})
	record(t, b, tool, ev, sdk.TaskCompleted, 0)
	r := snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Complete || r.Counts["completed_without_evidence"] != 1 {
		t.Fatalf("negative result hidden: %+v", r)
	}
	x := ev
	x.ID = "denied"
	x.Value = "denied.example.com"
	x.Target = event.Target{}
	x.Meta = map[string]string{"deny": "resolve"}
	publish(t, b, x)
	r = snapshot(t, b, []sdk.Definition{tool}, "run1")
	if len(r.Items) != 1 {
		t.Fatal("deny ignored")
	}
	record(t, b, tool, ev, sdk.TaskCompleted, 1)
	stream, err := b.JS.Stream(context.Background(), sdk.StreamName)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.DeleteMsg(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	r = snapshot(t, b, []sdk.Definition{tool}, "run1")
	if r.Complete || len(r.Warnings) == 0 {
		t.Fatalf("missing history certified: %+v", r)
	}
}

func TestUnknownWorkerRegistersItselfAndRemainsExpectedOffline(t *testing.T) {
	b, url := busAt(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := sdk.Config{Name: "custom-not-in-any-tool-list", URL: url, Kinds: []event.Kind{event.KindURL}, Filter: sdk.FieldIn("name", "wanted.invalid"),
		Handle: func(context.Context, event.Event) ([]event.Event, error) { return nil, nil }}
	in := publish(t, b, event.Event{ID: "wanted", Kind: event.KindURL, Value: "https://wanted.invalid", Target: event.Target{Host: "192.0.2.1"}})
	publish(t, b, event.Event{ID: "ignored", Kind: event.KindURL, Value: "https://ignored.invalid"})
	done := make(chan error, 1)
	go func() { done <- sdk.Run(ctx, cfg) }()
	deadline := time.Now().Add(5 * time.Second)
	completed := false
	for time.Now().Before(deadline) {
		if entry, err := b.KV.Get(ctx, sdk.WorkKey(cfg, in)); err == nil {
			var task sdk.Task
			if err := json.Unmarshal(entry.Value(), &task); err != nil {
				t.Fatal(err)
			}
			if task.Status == sdk.TaskCompleted {
				completed = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("registered worker did not process retained input")
	}
	if err := b.SetInventory(context.Background(), []string{cfg.Name}, true); err != nil {
		t.Fatal(err)
	}
	r, err := Snapshot(context.Background(), b, Filter{Run: "run1"})
	if err != nil || !r.Complete || len(r.Items) != 1 {
		t.Fatalf("runtime and persisted eligibility differ: %+v %v", r, err)
	}
	later := in
	later.ID, later.Value = "late", "https://wanted.invalid/Late"
	later.URL = ""
	publish(t, b, later)
	r, err = Snapshot(context.Background(), b, Filter{Run: "run1"})
	if err != nil || r.Complete || r.Counts["unclaimed"] != 1 || r.Counts[sdk.TaskCompleted] != 1 {
		t.Fatalf("offline worker disappeared: %+v %v", r, err)
	}
}

func TestInventoryPreventsFalseCompletionForNeverRegisteredWorkers(t *testing.T) {
	b := bus(t)
	d := (sdk.Config{Name: "sink", Kinds: []event.Kind{event.KindIP}}).Definition()
	in := publish(t, b, event.Event{ID: "seed", Kind: event.KindIP, Value: "192.0.2.1"})
	if _, err := b.Register(context.Background(), d, false); err != nil {
		t.Fatal(err)
	}
	record(t, b, d, in, sdk.TaskCompleted, 0)
	r, err := Snapshot(context.Background(), b, Filter{Run: "run1"})
	if err != nil || r.Complete || !strings.Contains(strings.Join(r.Warnings, " "), "inventory has not") {
		t.Fatalf("unknown deployment certified: %+v %v", r, err)
	}
	if err := b.SetInventory(context.Background(), []string{"sink", "never-registered"}, true); err != nil {
		t.Fatal(err)
	}
	r, err = Snapshot(context.Background(), b, Filter{Run: "run1"})
	if err != nil || r.Complete || !strings.Contains(strings.Join(r.Warnings, " "), "never-registered") {
		t.Fatalf("missing worker hidden: %+v %v", r, err)
	}
	if err := b.SetInventory(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	r, err = Snapshot(context.Background(), b, Filter{Run: "run1"})
	if err != nil || r.Complete || !strings.Contains(strings.Join(r.Warnings, " "), "registration is incomplete") {
		t.Fatalf("interrupted deployment certified: %+v %v", r, err)
	}
}

func TestCustomRulesAlsoFilterPrerequisitePlanning(t *testing.T) {
	d := (sdk.Config{Name: "custom-bound-worker", Kinds: []event.Kind{event.KindFQDN}, NeedBinding: true, Filter: sdk.FieldIn("name", "selected.example.com")}).Definition()
	p := newPlanner([]sdk.Definition{d})
	for _, ev := range []event.Event{
		{Kind: event.KindFQDN, Value: "ignored.example.com", Target: event.Target{Name: "ignored.example.com"}},
		{Kind: event.KindDomain, Value: "ignored.example.com", Target: event.Target{Name: "ignored.example.com"}},
		{Kind: event.KindFQDN, Value: "selected.example.com", Target: event.Target{Name: "selected.example.com"}},
	} {
		p.add(ev)
	}
	wanted := p.expectations()
	if len(wanted) != 1 {
		t.Fatalf("custom filter created unrelated prerequisites: %+v", wanted)
	}
	for _, item := range wanted {
		if item.ev.Name != "selected.example.com" || item.blocked != "blocked_resolution" {
			t.Fatalf("wrong prerequisite: %+v", item)
		}
	}
}
