package sdk

import (
	"adama/event"
	"context"
	"testing"
	"time"
)

func TestScanLineageAndObservationSink(t *testing.T) {
	url := startJS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	observed := make(chan event.Event, 8)
	configs := []Config{
		{Name: "schema-reporter", URL: url, Kinds: []event.Kind{event.KindService}, Observe: true, Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) { observed <- ev; return nil, nil }},
		{Name: "schema-probe", URL: url, Kinds: []event.Kind{event.KindFQDN}, Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
			var out []event.Event
			for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
				out = append(out, event.Event{Kind: event.KindService, Value: "app.example.com:8443/http", Probe: "service-detection", Service: "http", TLS: true,
					Target: event.Target{Host: ip, Name: ev.Name, NameRole: event.NameRequested, Port: 8443, Proto: event.TCP}, Info: map[string]string{"version": "1"}})
			}
			return out, nil
		}},
	}
	done := make(chan error, len(configs))
	for _, cfg := range configs {
		go func() { done <- Run(ctx, cfg) }()
	}
	t.Cleanup(func() {
		cancel()
		for range configs {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("worker did not stop")
			}
		}
	})
	for _, cfg := range configs {
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := b.JS.Consumer(ctx, StreamName, cfg.Name); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("consumer was not created")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	seed := event.Event{ID: "seed", RunID: "campaign", Kind: event.KindFQDN, Value: "app.example.com", Meta: map[string]string{"scope": "test", "deny": "unused"}}
	if err := b.Publish(ctx, seed); err != nil {
		t.Fatal(err)
	}
	next := func() event.Event {
		t.Helper()
		select {
		case ev := <-observed:
			return ev
		case <-time.After(3 * time.Second):
			t.Fatal("missing observation")
			return event.Event{}
		}
	}
	a, c := next(), next()
	if a.ScanID == "" || a.ScanID != c.ScanID || a.ID == c.ID || a.Host == c.Host {
		t.Fatalf("lost scan/endpoint identity %+v %+v", a, c)
	}
	for _, ev := range []event.Event{a, c} {
		if ev.SchemaVersion != 2 || ev.RunID != "campaign" || ev.ParentID != "seed" || ev.Source != "schema-probe" || ev.Input == nil || ev.Input.Value != "app.example.com" || ev.Meta["scope"] != "test" || ev.Meta["deny"] != "unused" {
			t.Fatalf("lost lineage or gate: %+v", ev)
		}
	}
	// A distinct observation of the same service must reach the sink too.
	a.ID = "enrichment"
	a.Info = map[string]string{"version": "2"}
	if err := b.Publish(ctx, a); err != nil {
		t.Fatal(err)
	}
	enriched := next()
	if enriched.ID != "enrichment" || enriched.Info["version"] != "2" {
		t.Fatalf("enrichment was suppressed %+v", enriched)
	}
}
