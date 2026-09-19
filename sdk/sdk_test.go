package sdk

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"

	natsserver "github.com/nats-io/nats-server/v2/server"
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
