package reconcile

import (
	"context"
	"testing"
	"time"

	"adama/event"
	"adama/sdk"
	natsserver "github.com/nats-io/nats-server/v2/server"
)

func newTestStore(t *testing.T) (*Store, *sdk.Bus) {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{JetStream: true, StoreDir: t.TempDir(), Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(s.Shutdown)
	b, err := sdk.Connect(context.Background(), s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	store, err := New(context.Background(), b.JS)
	if err != nil {
		t.Fatal(err)
	}
	return store, b
}

func TestLateNameAndLatePortProduceSameEndpoints(t *testing.T) {
	for _, nameFirst := range []bool{true, false} {
		label := "port-first"
		if nameFirst {
			label = "name-first"
		}
		t.Run(label, func(t *testing.T) {
			store, b := newTestStore(t)
			name := event.Event{ID: "dns", Kind: event.KindFQDN, Value: "late.example.com", Target: event.Target{Host: "192.0.2.1", Name: "late.example.com", NameRole: event.NameDNSA}, Meta: map[string]string{"scope": "test"}}
			port := event.Event{ID: "open", Kind: event.KindPort, Value: "192.0.2.1:45678", Target: event.Target{Host: "192.0.2.1", Port: 45678, Proto: event.TCP}, Meta: map[string]string{"scope": "test"}}
			first, second := port, name
			if nameFirst {
				first, second = name, port
			}
			if got, err := store.Handle(context.Background(), first); err != nil || len(got) != 0 {
				t.Fatalf("premature join %+v %v", got, err)
			}
			// Recreate the worker's store between arrivals to exercise persistence.
			store, err := New(context.Background(), b.JS)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.Handle(context.Background(), second)
			if err != nil || len(got) != 1 {
				t.Fatalf("missing join %+v %v", got, err)
			}
			out, err := got[0].Canonical()
			if err != nil || out.Host != "192.0.2.1" || out.Value != "late.example.com:45678" || out.Proto != event.TCP || out.Info["name_event_id"] != "dns" || out.Info["port_event_id"] != "open" {
				t.Fatalf("wrong endpoint %+v %v", out, err)
			}
			out.Source = "reconcile"
			if extra, err := store.Handle(context.Background(), out); err != nil || len(extra) != 0 {
				t.Fatal("join fed itself")
			}
		})
	}
}

func TestJoinRespectsEvidenceTransportScopeAndGates(t *testing.T) {
	store, _ := newTestStore(t)
	name := event.Event{Kind: event.KindFQDN, Value: "app.example.com", Target: event.Target{Host: "192.0.2.1", Name: "app.example.com", NameRole: event.NameCertSAN}, Meta: map[string]string{"scope": "a", "allow": "reconcile,nmap-svc,httpx", "deny": "nuclei"}}
	port := event.Event{Kind: event.KindPort, Value: "192.0.2.1:53", Target: event.Target{Host: "192.0.2.1", Port: 53, Proto: event.UDP}, Meta: map[string]string{"scope": "a", "allow": "reconcile,nmap-svc"}}
	if _, err := store.Handle(context.Background(), port); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Handle(context.Background(), name); err != nil || len(got) != 0 {
		t.Fatal("certificate was treated as DNS")
	}
	name.NameRole = event.NameDNSA
	name.Host = "192.0.2.2"
	if got, err := store.Handle(context.Background(), name); err != nil || len(got) != 0 {
		t.Fatal("joined another backend")
	}
	name.Host = "192.0.2.1"
	name.Meta["scope"] = "b"
	if got, err := store.Handle(context.Background(), name); err != nil || len(got) != 0 {
		t.Fatal("joined another scope")
	}
	name.Meta["scope"] = "a"
	got, err := store.Handle(context.Background(), name)
	if err != nil || len(got) != 1 || got[0].Proto != event.UDP || event.Allowed("httpx", got[0].Meta) || event.Allowed("nuclei", got[0].Meta) || !event.Allowed("nmap-svc", got[0].Meta) {
		t.Fatalf("lost transport or broadened gate %+v %v", got, err)
	}
}
