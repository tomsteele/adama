package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"
	"github.com/nats-io/nats.go/jetstream"
)

func workTest(t *testing.T, handle func(context.Context, event.Event) ([]event.Event, error)) (*Bus, Config, jetstream.Consumer, event.Event) {
	t.Helper()
	b, err := Connect(context.Background(), startJS(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	cfg, err := (Config{Name: "work-test", Kinds: []event.Kind{event.KindIP}, Handle: handle,
		RetryDelay: 10 * time.Millisecond, LeaseDuration: 120 * time.Millisecond, AckWait: 90 * time.Millisecond, TaskTimeout: 3 * time.Second, ShutdownGrace: time.Second}).defaults()
	if err != nil {
		t.Fatal(err)
	}
	cons, err := b.consumer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := prepare(event.Event{ID: "input", Kind: event.KindIP, Value: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	return b, cfg, cons, ev
}

func nextWork(t *testing.T, cons jetstream.Consumer) jetstream.Msg {
	t.Helper()
	m, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readTask(t *testing.T, b *Bus, cfg Config, ev event.Event) Task {
	t.Helper()
	e, err := b.KV.Get(context.Background(), WorkKey(cfg, ev))
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	if err := json.Unmarshal(e.Value(), &task); err != nil {
		t.Fatal(err)
	}
	return task
}

func TestTerminalFailureSurvivesDuplicateAndReplay(t *testing.T) {
	var executions atomic.Int32
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) {
		executions.Add(1)
		return nil, errors.New("invalid tool arguments")
	})
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	for _, id := range []string{"duplicate-a", "duplicate-b"} {
		x := ev
		x.ID = id
		if err := b.Publish(context.Background(), x); err != nil {
			t.Fatal(err)
		}
		b.onMsg(context.Background(), cfg, nextWork(t, cons))
	}
	task := readTask(t, b, cfg, ev)
	if executions.Load() != 1 || task.Status != TaskFailed || task.Attempts != 1 || !strings.Contains(task.Error, "invalid tool") {
		t.Fatalf("repeated terminal work: %+v calls=%d", task, executions.Load())
	}
}

func TestTransientExecutionBudget(t *testing.T) {
	var executions atomic.Int32
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) {
		executions.Add(1)
		return nil, Retryable(errors.New("temporary connection failure"))
	})
	for range 3 {
		b.onMsg(context.Background(), cfg, nextWork(t, cons))
	}
	task := readTask(t, b, cfg, ev)
	if executions.Load() != 3 || task.Status != TaskFailed || task.Attempts != 3 {
		t.Fatalf("budget not enforced: %+v calls=%d", task, executions.Load())
	}
	ev.ID = "later-duplicate"
	if err := b.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	if executions.Load() != 3 {
		t.Fatal("duplicate reset retry budget")
	}
}

func TestExpiredLeaseRecoveryAndBudget(t *testing.T) {
	for _, attempts := range []int{1, 3} {
		t.Run(string(rune('0'+attempts)), func(t *testing.T) {
			var executions atomic.Int32
			b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) { executions.Add(1); return nil, nil })
			l, _, err := b.claim(cfg, ev)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.update(func(t *Task) {
				t.Attempts = attempts
				t.ResultKey = "interrupted"
				t.LeaseUntil = time.Now().Add(-time.Second)
			}); err != nil {
				t.Fatal(err)
			}
			b.onMsg(context.Background(), cfg, nextWork(t, cons))
			task := readTask(t, b, cfg, ev)
			if attempts == 1 && (executions.Load() != 1 || task.Status != TaskCompleted || task.Attempts != 2) {
				t.Fatalf("unfinished task lost: %+v", task)
			}
			if attempts == 3 && (executions.Load() != 0 || task.Status != TaskFailed) {
				t.Fatalf("crash reset budget: %+v", task)
			}
			if err := l.update(func(t *Task) { t.Status = TaskCompleted }); err == nil {
				t.Fatal("stale owner overwrote replacement")
			}
		})
	}
}

func TestSavedOutputResumesWithoutScan(t *testing.T) {
	for _, status := range []string{TaskRunning, TaskPublishing} {
		t.Run(status, func(t *testing.T) {
			var executions atomic.Int32
			b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) { executions.Add(1); return nil, nil })
			l, _, err := b.claim(cfg, ev)
			if err != nil {
				t.Fatal(err)
			}
			child, err := prepare(event.Event{ID: "stable-output", Kind: event.KindPort, Value: "192.0.2.1:443"})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(savedResult{Events: []event.Event{child}})
			if _, err := b.Outbox.PutBytes(context.Background(), "saved-batch", raw); err != nil {
				t.Fatal(err)
			}
			if err := l.update(func(t *Task) {
				t.Status = status
				t.Attempts = 1
				t.ResultKey = "saved-batch"
				t.LeaseUntil = time.Now().Add(-time.Second)
			}); err != nil {
				t.Fatal(err)
			}
			b.onMsg(context.Background(), cfg, nextWork(t, cons))
			task := readTask(t, b, cfg, ev)
			if executions.Load() != 0 || task.Status != TaskCompleted || task.NextOutput != 1 || task.Attempts != 1 {
				t.Fatalf("saved results reran scanner: %+v", task)
			}
			stream, err := b.JS.Stream(context.Background(), StreamName)
			if err != nil {
				t.Fatal(err)
			}
			out, err := stream.GetLastMsgForSubject(context.Background(), event.Subject(event.KindPort))
			if err != nil {
				t.Fatal(err)
			}
			got, err := event.Decode(out.Data)
			if err != nil || got.ID != "stable-output" {
				t.Fatalf("unstable output %+v %v", got, err)
			}
		})
	}
}

func TestHeartbeatProtectsLongHandler(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) { close(started); <-release; return nil, nil })
	done := make(chan struct{})
	go func() { b.onMsg(context.Background(), cfg, nextWork(t, cons)); close(done) }()
	<-started
	time.Sleep(250 * time.Millisecond) // Exceeds both lease duration and AckWait.
	l, delay, err := b.claim(cfg, ev)
	if err != nil || l != nil || delay <= 0 {
		t.Fatalf("active work was stolen: %v %v %v", l, delay, err)
	}
	info, err := cons.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.NumRedelivered != 0 {
		t.Fatalf("missing in-progress heartbeat: %+v", info)
	}
	close(release)
	<-done
	if readTask(t, b, cfg, ev).Status != TaskCompleted {
		t.Fatal("long task did not finish")
	}
}

func TestPublishFailuresDoNotRepeatScanner(t *testing.T) {
	var executions atomic.Int32
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) {
		executions.Add(1)
		return []event.Event{{Kind: event.KindPort, Value: "192.0.2.1:443", Info: map[string]string{"large": strings.Repeat("x", 2048)}}}, nil
	})
	stream, err := b.JS.Stream(context.Background(), StreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info.Config.MaxMsgSize = 1024
	if _, err := b.JS.UpdateStream(context.Background(), info.Config); err != nil {
		t.Fatal(err)
	}
	for range cfg.MaxPublishAttempts + 1 {
		b.onMsg(context.Background(), cfg, nextWork(t, cons))
	}
	task := readTask(t, b, cfg, ev)
	if executions.Load() != 1 || task.Status != TaskFailed || task.PublishAttempts != cfg.MaxPublishAttempts || task.ResultKey == "" {
		t.Fatalf("publication loop reran scanner or lost output %+v", task)
	}
}

func TestLateConsumerAndConfigDrift(t *testing.T) {
	b, cfg, _, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) { return nil, nil })
	cfg.Name = "late-tool"
	cons, err := b.consumer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	if readTask(t, b, cfg, ev).Status != TaskCompleted {
		t.Fatal("late worker missed retained input")
	}
	cfg.Kinds = []event.Kind{event.KindFQDN}
	if _, err := b.consumer(context.Background(), cfg); err == nil {
		t.Fatal("silently accepted stale subscription")
	}
}

func TestSharedToolFailurePausesNewExecutions(t *testing.T) {
	var executions atomic.Int32
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) {
		if executions.Add(1) == 1 {
			return nil, ToolUnavailable(errors.New("broken installation"))
		}
		return nil, nil
	})
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	ev.ID, ev.Value, ev.Host = "second", "192.0.2.2", "192.0.2.2"
	if err := b.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	if executions.Load() != 1 {
		t.Fatal("broken installation kept consuming targets")
	}
	if err := b.Tools.Delete(context.Background(), cfg.Name); err != nil {
		t.Fatal(err)
	}
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	if executions.Load() != 2 || readTask(t, b, cfg, ev).Status != TaskCompleted {
		t.Fatal("resume did not release pending work")
	}
}

func TestPartialResultsSurviveTerminalFailure(t *testing.T) {
	b, cfg, cons, ev := workTest(t, func(context.Context, event.Event) ([]event.Event, error) {
		return []event.Event{{Kind: event.KindPort, Value: "192.0.2.1:443"}}, errors.New("tool exited after partial output")
	})
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	task := readTask(t, b, cfg, ev)
	if task.Status != TaskFailed || task.Emitted != 1 || task.Attempts != 1 {
		t.Fatalf("partial success hid failure or lost evidence %+v", task)
	}
}

func TestShutdownPersistsAttemptBeforeReplacement(t *testing.T) {
	url := startJS(t)
	b, err := Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	started := make(chan struct{})
	cfg := Config{Name: "shutdown", URL: url, Kinds: []event.Kind{event.KindIP}, RetryDelay: 10 * time.Millisecond, Handle: func(ctx context.Context, _ event.Event) ([]event.Event, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	ev, err := prepare(event.Event{ID: "shutdown-input", Kind: event.KindIP, Value: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not drain")
	}
	task := readTask(t, b, cfg, ev)
	if task.Status != TaskRetry || task.Attempts != 1 || task.Owner != "" {
		t.Fatalf("shutdown lost progress %+v", task)
	}
	cfg.Handle = func(context.Context, event.Event) ([]event.Event, error) { return nil, nil }
	cfg, err = cfg.defaults()
	if err != nil {
		t.Fatal(err)
	}
	cons, err := b.consumer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.onMsg(context.Background(), cfg, nextWork(t, cons))
	task = readTask(t, b, cfg, ev)
	if task.Status != TaskCompleted || task.Attempts != 2 {
		t.Fatalf("replacement reset or lost attempt %+v", task)
	}
}
