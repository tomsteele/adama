package sdk

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func startJS(t *testing.T) string {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{
		JetStream: true,
		StoreDir:  t.TempDir(),
		Port:      -1,
		NoLog:     true,
		NoSigs:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(s.Shutdown)
	return s.ClientURL()
}

func TestFanoutAndDedup(t *testing.T) {
	url := startJS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var a, b atomic.Int32
	var wg sync.WaitGroup
	start := func(name string, n *atomic.Int32) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Run(ctx, Config{
				Name:  name,
				URL:   url,
				Kinds: []event.Kind{event.KindPort},
				Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
					n.Add(1)
					return nil, nil
				},
			})
		}()
	}
	start("tool-a", &a)
	start("tool-b", &b)
	time.Sleep(400 * time.Millisecond)

	if err := Seed(ctx, url, event.Event{Kind: event.KindPort, Value: "example.com:443"}); err != nil {
		t.Fatal(err)
	}
	wait(t, &a, 1)
	wait(t, &b, 1)

	if err := Seed(ctx, url, event.Event{Kind: event.KindPort, Value: "Example.COM:443"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if a.Load() != 1 || b.Load() != 1 {
		t.Fatalf("dedup failed a=%d b=%d", a.Load(), b.Load())
	}
	cancel()
	wg.Wait()
}

func TestNeedLive(t *testing.T) {
	url := startJS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var n atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = Run(ctx, Config{
			Name:     "nmap-quick",
			URL:      url,
			Kinds:    []event.Kind{event.KindIP},
			NeedLive: true,
			Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
				n.Add(1)
				return nil, nil
			},
		})
	}()
	time.Sleep(400 * time.Millisecond)
	if err := Seed(ctx, url, event.Event{Kind: event.KindIP, Value: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatal("seed must not scan")
	}
	b, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, event.Event{Kind: event.KindIP, Value: "1.2.3.4", Source: "http-probe", Meta: event.MarkLive(nil)}); err != nil {
		t.Fatal(err)
	}
	wait(t, &n, 1)
	b.Close()
	cancel()
	wg.Wait()
}

func TestActivity(t *testing.T) {
	url := startJS(t)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	ch := make(chan event.Activity, 8)
	if _, err := nc.Subscribe(event.ActivitySubject, func(m *nats.Msg) {
		a, err := event.DecodeActivity(m.Data)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- a
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = Run(ctx, Config{
			Name:  "tool-a",
			URL:   url,
			Kinds: []event.Kind{event.KindPort},
			Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
				return nil, nil
			},
		})
	}()
	time.Sleep(400 * time.Millisecond)
	if err := Seed(ctx, url, event.Event{Kind: event.KindPort, Value: "example.com:443"}); err != nil {
		t.Fatal(err)
	}

	var got []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(got) < 2 {
		select {
		case a := <-ch:
			got = append(got, a.Action)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if len(got) < 2 || got[0] != "start" || got[1] != "done" {
		t.Fatalf("actions %v", got)
	}
	cancel()
	wg.Wait()
}

func wait(t *testing.T, n *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n.Load() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("got %d want %d", n.Load(), want)
}
