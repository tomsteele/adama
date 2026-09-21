package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"adama/event"
	"github.com/nats-io/nats.go/jetstream"
)

func registryBus(t *testing.T) *Bus {
	t.Helper()
	b, err := Connect(context.Background(), startJS(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestRulesRoundTripAndRejectUnknownPredicates(t *testing.T) {
	rule := All(Has("host"), Any(FieldIn("kind", "port"), BoundNameRule()), Not(FieldIn("source", "my-worker")))
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rule)
	var decoded Rule
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []event.Event{
		{Kind: event.KindPort, Target: event.Target{Host: "192.0.2.1"}},
		{Kind: event.KindFQDN, Target: event.Target{Host: "192.0.2.1", Name: "example.com", NameRole: event.NameDNSA}},
		{Kind: event.KindPort, Source: "my-worker", Target: event.Target{Host: "192.0.2.1"}},
		{Kind: event.KindFQDN, Target: event.Target{Host: "192.0.2.1", Name: "example.com", NameRole: event.NameCertSAN}},
	} {
		if rule.Match(ev) != decoded.Match(ev) {
			t.Fatalf("registration changed predicate for %+v", ev)
		}
	}
	if !decoded.Match(event.Event{Kind: event.KindPort, Target: event.Target{Host: "192.0.2.1"}}) {
		t.Fatal("valid endpoint rejected")
	}
	if decoded.Match(event.Event{Kind: event.KindPort, Source: "my-worker", Target: event.Target{Host: "192.0.2.1"}}) {
		t.Fatal("self-generated input accepted")
	}
	for _, bad := range []Rule{FieldIn("typo", "x"), {Field: "host"}, {All: []Rule{}}, {Field: "host", Present: true, Values: []string{"x"}}, {All: []Rule{{}}, Any: []Rule{{}}}} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid predicate accepted: %+v", bad)
		}
	}
}

func TestRegistrationReplicasAndConflicts(t *testing.T) {
	b := registryBus(t)
	ctx := context.Background()
	d := (Config{Name: "custom-worker", Kinds: []event.Kind{event.KindURL, event.KindService}, Filter: Not(FieldIn("source", "custom-worker")), Observe: true}).Definition()
	first, err := b.Register(ctx, d, false)
	if err != nil {
		t.Fatal(err)
	}
	d.Kinds = []event.Kind{event.KindService, event.KindURL, event.KindURL}
	replica, err := b.Register(ctx, d, false)
	if err != nil || first.Fingerprint != replica.Fingerprint || !first.Registered.Equal(replica.Registered) {
		t.Fatalf("replica drift: %+v %v", replica, err)
	}
	d.NeedLive = true
	if _, err := b.Register(ctx, d, false); err == nil {
		t.Fatal("different replica silently overwrote definition")
	}
	list, err := b.Registrations(ctx)
	if err != nil || len(list) != 1 || list[0].Definition.NeedLive {
		t.Fatalf("lost original definition: %+v %v", list, err)
	}
	if _, err := b.Register(ctx, d, true); err != nil {
		t.Fatal(err)
	}
	list, err = b.Registrations(ctx)
	if err != nil || !list[0].Definition.NeedLive {
		t.Fatal("explicit replacement failed")
	}
	d.Version = 99
	if _, err := b.Register(ctx, d, true); err == nil {
		t.Fatal("unsupported definition version accepted")
	}
}

func TestRegisterOnlyDoesNotRunSetupCheckBinariesOrConsume(t *testing.T) {
	t.Setenv("ADAMA_REGISTER_ONLY", "1")
	url := startJS(t)
	calls := 0
	cfg := Config{Name: "unstarted-tool", URL: url, Kinds: []event.Kind{event.KindIP}, NeedLive: true, Evidence: "open endpoint",
		RequiredTools: []string{"adama-test-nonexistent-binary"},
		Setup:         func(context.Context, *Bus) error { calls++; return nil },
		Handle:        func(context.Context, event.Event) ([]event.Event, error) { calls++; return nil, nil }}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	b, err := Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	list, err := b.Registrations(context.Background())
	if err != nil || len(list) != 1 || list[0].Definition.Name != cfg.Name || !list[0].Definition.NeedLive || calls != 0 {
		t.Fatalf("invalid register-only behavior: %+v %v calls=%d", list, err, calls)
	}
	if _, err := b.JS.Consumer(context.Background(), StreamName, cfg.Name); !errors.Is(err, jetstream.ErrConsumerNotFound) {
		t.Fatalf("register-only created consumer: %v", err)
	}
}

func TestBrokenInstallationStillRegistersExpectedWorker(t *testing.T) {
	url := startJS(t)
	err := Run(context.Background(), Config{Name: "broken-install", URL: url, Kinds: []event.Kind{event.KindIP}, RequiredTools: []string{"adama-test-nonexistent-binary"}, Handle: func(context.Context, event.Event) ([]event.Event, error) { t.Error("handler ran"); return nil, nil }})
	if err == nil || !strings.Contains(err.Error(), "prerequisite") {
		t.Fatalf("missing prerequisite accepted: %v", err)
	}
	b, err := Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	list, err := b.Registrations(context.Background())
	if err != nil || len(list) != 1 || list[0].Definition.Name != "broken-install" {
		t.Fatalf("broken worker disappeared: %+v %v", list, err)
	}
}
