package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"adama/event"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"
)

const (
	WorkBucket     = "ADAMA_WORK"
	OutboxBucket   = "ADAMA_OUTBOX"
	TaskRunning    = "running"
	TaskPublishing = "publishing"
	TaskRetry      = "retry_wait"
	TaskCompleted  = "completed"
	TaskFailed     = "failed"
)

// Task is durable coverage and execution state, not a new event kind. No TTL:
// replay, duplicate inputs and worker replacement cannot reset its budget.
type Task struct {
	Key                string       `json:"key"`
	Tool               string       `json:"tool"`
	EventID            string       `json:"event_id"`
	RunID              string       `json:"run_id,omitempty"`
	Scope              string       `json:"scope,omitempty"`
	Input              *event.Input `json:"input"`
	Status             string       `json:"status"`
	Attempts           int          `json:"attempts"`
	MaxAttempts        int          `json:"max_attempts"`
	PublishAttempts    int          `json:"publish_attempts"`
	MaxPublishAttempts int          `json:"max_publish_attempts"`
	Owner              string       `json:"owner,omitempty"`
	LeaseUntil         time.Time    `json:"lease_until,omitempty"`
	NextAttempt        time.Time    `json:"next_attempt,omitempty"`
	Deadline           time.Time    `json:"deadline"`
	Created            time.Time    `json:"created_at"`
	Updated            time.Time    `json:"updated_at"`
	ScanID             string       `json:"scan_id,omitempty"`
	ResultKey          string       `json:"result_key,omitempty"`
	NextOutput         int          `json:"next_output"`
	Emitted            int          `json:"emitted"`
	Error              string       `json:"error,omitempty"`
}

type savedResult struct {
	Events  []event.Event `json:"events"`
	Error   string        `json:"error,omitempty"`
	Retry   bool          `json:"retry,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns,omitempty"`
}

var errInvalidResult = errors.New("invalid saved result")

type workLease struct {
	mu       sync.Mutex
	b        *Bus
	task     Task
	revision uint64
}

func WorkKey(cfg Config, ev event.Event) string {
	if cfg.Observe {
		return fmt.Sprintf("observe/%x", sha256.Sum256([]byte(cfg.Name+"\x00"+ev.ID)))
	}
	return event.DedupKey(cfg.Name, ev)
}

func operationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func (l *workLease) snapshot() Task {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.task
}

// All owner writes use compare-and-swap, including heartbeats and completion.
func (l *workLease) update(change func(*Task)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.task
	change(&t)
	t.Updated = time.Now().UTC()
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	ctx, cancel := operationContext()
	defer cancel()
	rev, err := l.b.KV.Update(ctx, t.Key, raw, l.revision)
	if err != nil {
		return err
	}
	l.task, l.revision = t, rev
	return nil
}

func (b *Bus) claim(cfg Config, ev event.Event) (*workLease, time.Duration, error) {
	key := WorkKey(cfg, ev)
	ctx, cancel := operationContext()
	defer cancel()
	entry, err := b.KV.Get(ctx, key)
	now := time.Now().UTC()
	t := Task{Key: key, Tool: cfg.Name, EventID: ev.ID, RunID: ev.RunID, Scope: ev.Meta["scope"], Input: ev.AsInput(),
		Status: TaskRunning, MaxAttempts: cfg.MaxAttempts, MaxPublishAttempts: cfg.MaxPublishAttempts,
		Created: now, Deadline: now.Add(cfg.RetryWindow)}
	var revision uint64
	if err == nil {
		if err := json.Unmarshal(entry.Value(), &t); err != nil {
			return nil, 0, fmt.Errorf("invalid work state: %w", err)
		}
		revision = entry.Revision()
		if t.Status == TaskCompleted || t.Status == TaskFailed {
			return nil, 0, nil
		}
		if t.LeaseUntil.After(now) {
			return nil, time.Until(t.LeaseUntil), nil
		}
		if t.NextAttempt.After(now) {
			return nil, time.Until(t.NextAttempt), nil
		}
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, 0, err
	}
	t.Owner, t.LeaseUntil, t.Updated = nuid.Next(), now.Add(cfg.LeaseDuration), now
	raw, _ := json.Marshal(t)
	if revision == 0 {
		revision, err = b.KV.Create(ctx, key, raw)
	} else {
		revision, err = b.KV.Update(ctx, key, raw, revision)
	}
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return nil, cfg.RetryDelay, nil
		}
		return nil, 0, err
	}
	return &workLease{b: b, task: t, revision: revision}, 0, nil
}

func (l *workLease) heartbeat(ctx context.Context, cfg Config, msg jetstream.Msg, cancel context.CancelFunc) func() {
	interval := min(cfg.LeaseDuration/3, cfg.AckWait/3)
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := l.update(func(t *Task) {
					if t.Owner != "" {
						t.LeaseUntil = time.Now().UTC().Add(cfg.LeaseDuration)
					}
				}); err != nil {
					cancel()
					return
				}
				if err := msg.InProgress(); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(done); <-stopped }
}

func retryDelay(cfg Config, attempt int) time.Duration {
	base := cfg.RetryDelay * time.Duration(1<<min(max(attempt-1, 0), 6))
	base = min(base, 10*time.Minute)
	return base + time.Duration(rand.Int64N(max(int64(base/4), 1)))
}

func (b *Bus) loadResult(key string) (savedResult, error) {
	var result savedResult
	if key == "" {
		return result, jetstream.ErrObjectNotFound
	}
	ctx, cancel := operationContext()
	defer cancel()
	raw, err := b.Outbox.GetBytes(ctx, key)
	if err == nil {
		if decodeErr := json.Unmarshal(raw, &result); decodeErr != nil {
			err = fmt.Errorf("%w: %v", errInvalidResult, decodeErr)
		}
	}
	return result, err
}

func (l *workLease) finish(status, reason string) error {
	return l.update(func(t *Task) {
		t.Status, t.Error, t.Owner = status, reason, ""
		t.LeaseUntil, t.NextAttempt = time.Time{}, time.Time{}
	})
}

func invoke(ctx context.Context, cfg Config, ev event.Event) ([]event.Event, error) {
	type response struct {
		events []event.Event
		err    error
	}
	ch := make(chan response, 1)
	go func() {
		var r response
		defer func() {
			if p := recover(); p != nil {
				r.err = fmt.Errorf("handler panic: %v", p)
			}
			ch <- r
		}()
		r.events, r.err = cfg.Handle(ctx, ev)
	}()
	select {
	case r := <-ch:
		return r.events, r.err
	case <-ctx.Done():
		timer := time.NewTimer(cfg.ShutdownGrace)
		defer timer.Stop()
		select {
		case r := <-ch:
			return r.events, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("handler did not stop after cancellation")
		}
	}
}

func (b *Bus) process(ctx context.Context, cfg Config, ev event.Event, msg jetstream.Msg) error {
	l, delay, err := b.claim(cfg, ev)
	if err != nil {
		return err
	}
	if l == nil {
		if delay > 0 {
			return msg.NakWithDelay(max(delay, time.Millisecond))
		}
		b.note("skip", cfg.Name, ev, "work already completed or terminally failed", 0, 0)
		return msg.Ack()
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopHeartbeat := l.heartbeat(workCtx, cfg, msg, cancel)
	defer stopHeartbeat()
	t := l.snapshot()
	result, err := b.loadResult(t.ResultKey)
	if errors.Is(err, errInvalidResult) {
		if err := l.finish(TaskFailed, err.Error()); err != nil {
			return err
		}
		return msg.Ack()
	}
	if err != nil && !errors.Is(err, jetstream.ErrObjectNotFound) {
		return err
	}
	if errors.Is(err, jetstream.ErrObjectNotFound) {
		if t.Status == TaskPublishing {
			if err := l.finish(TaskFailed, "saved output is missing; scan will not be repeated"); err != nil {
				return err
			}
			return msg.Ack()
		}
		if t.Attempts >= t.MaxAttempts || time.Now().After(t.Deadline) {
			if err := l.finish(TaskFailed, "execution budget exhausted after interruption: "+t.Error); err != nil {
				return err
			}
			b.note("error", cfg.Name, ev, l.snapshot().Error, 0, 0)
			return msg.Ack()
		}
		if workCtx.Err() != nil {
			return workCtx.Err()
		}
		if err := l.update(func(t *Task) {
			t.Status, t.ScanID = TaskRunning, nuid.Next()
			t.ResultKey = t.ScanID
			t.Attempts++
			t.PublishAttempts, t.NextOutput = 0, 0
			t.NextAttempt = time.Time{}
		}); err != nil {
			return err
		}
		t = l.snapshot()
		b.note("start", cfg.Name, ev, "", 0, 0)
		attemptCtx, stop := context.WithTimeout(workCtx, cfg.TaskTimeout)
		started := time.Now()
		out, runErr := invoke(attemptCtx, cfg, ev)
		result.Elapsed = time.Since(started)
		stop()
		if runErr != nil {
			result.Error = runErr.Error()
			var unavailable toolUnavailableError
			if errors.As(runErr, &unavailable) {
				if err := b.pauseTool(cfg.Name, runErr.Error()); err != nil {
					return err
				}
			}
			var retry retryableError
			result.Retry = errors.As(runErr, &retry) || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)
		}
		for _, child := range out {
			if child.SchemaVersion == 0 {
				child.SchemaVersion = event.SchemaVersion
			}
			child.Source, child.ParentID, child.RunID, child.ScanID = cfg.Name, t.EventID, t.RunID, t.ScanID
			if child.Input == nil {
				child.Input = t.Input
			}
			if child.Probe == "" {
				child.Probe = cfg.Name
			}
			child = event.InheritGate(ev, child)
			child, err = prepare(child)
			if err != nil {
				result.Error, result.Retry = "invalid output: "+err.Error(), false
				continue
			}
			result.Events = append(result.Events, child)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		// Persist before publication. ResultKey was committed before execution,
		// so a replacement can find a batch saved just before the worker died.
		saveCtx, saveCancel := operationContext()
		_, err = b.Outbox.PutBytes(saveCtx, t.ResultKey, raw)
		saveCancel()
		if err != nil {
			return err
		}
	}
	if err := l.update(func(t *Task) { t.Status = TaskPublishing }); err != nil {
		return err
	}
	return b.publishResult(workCtx, l, cfg, ev, msg, result)
}

func (b *Bus) publishResult(ctx context.Context, l *workLease, cfg Config, ev event.Event, msg jetstream.Msg, result savedResult) error {
	t := l.snapshot()
	if t.NextOutput < len(result.Events) && t.PublishAttempts >= t.MaxPublishAttempts {
		if err := l.finish(TaskFailed, "publication budget exhausted; saved output retained: "+t.Error); err != nil {
			return err
		}
		b.note("error", cfg.Name, ev, l.snapshot().Error, 0, 0)
		return msg.Ack()
	}
	if t.NextOutput < len(result.Events) {
		if err := l.update(func(t *Task) { t.PublishAttempts++ }); err != nil {
			return err
		}
	}
	for i := t.NextOutput; i < len(result.Events); i++ {
		if ctx.Err() != nil {
			if err := l.update(func(t *Task) { t.Owner = ""; t.LeaseUntil = time.Time{} }); err != nil {
				return err
			}
			return msg.NakWithDelay(cfg.RetryDelay)
		}
		pubCtx, cancel := operationContext()
		err := b.Publish(pubCtx, result.Events[i])
		cancel()
		if err != nil {
			delay := retryDelay(cfg, l.snapshot().PublishAttempts)
			if err2 := l.update(func(t *Task) {
				t.Error = "publish: " + err.Error()
				t.Owner, t.LeaseUntil, t.NextAttempt = "", time.Time{}, time.Now().UTC().Add(delay)
			}); err2 != nil {
				return err2
			}
			b.note("error", cfg.Name, ev, "publication deferred: "+err.Error(), 0, 0)
			return msg.NakWithDelay(delay)
		}
		if err := l.update(func(t *Task) { t.NextOutput = i + 1; t.Emitted++ }); err != nil {
			return err
		}
	}
	t = l.snapshot()
	if result.Error != "" && result.Retry && t.Attempts < t.MaxAttempts && time.Now().Before(t.Deadline) {
		delay := retryDelay(cfg, t.Attempts)
		if err := l.update(func(t *Task) {
			t.Status, t.Error, t.ResultKey, t.Owner = TaskRetry, result.Error, "", ""
			t.LeaseUntil, t.NextAttempt = time.Time{}, time.Now().UTC().Add(delay)
		}); err != nil {
			return err
		}
		b.note("error", cfg.Name, ev, fmt.Sprintf("attempt %d/%d; retry scheduled: %s", t.Attempts, t.MaxAttempts, result.Error), len(result.Events), 0)
		return msg.NakWithDelay(delay)
	}
	status, action := TaskCompleted, "done"
	if result.Error != "" {
		status, action = TaskFailed, "error"
	}
	if err := l.finish(status, result.Error); err != nil {
		return err
	}
	b.note(action, cfg.Name, ev, result.Error, len(result.Events), result.Elapsed)
	return msg.Ack()
}

func (b *Bus) onMsg(ctx context.Context, cfg Config, msg jetstream.Msg) {
	ev, err := event.Decode(msg.Data())
	if err == nil {
		ev, err = ev.Canonical()
	}
	if err != nil {
		slog.Error("invalid event", "err", err)
		_ = msg.Term()
		return
	}
	if ev.ID == "" {
		if metadata, err := msg.Metadata(); err == nil {
			ev.ID = fmt.Sprintf("legacy-%s-%d", metadata.Stream, metadata.Sequence.Stream)
		}
	}
	if ev.RunID == "" && ev.ParentID == "" {
		ev.RunID = ev.ID
	}
	if !event.Allowed(cfg.Name, ev.Meta) || (cfg.NeedLive && !event.Live(ev)) {
		b.note("skip", cfg.Name, ev, "gate or liveness prerequisite", 0, 0)
		_ = msg.Ack()
		return
	}
	if cfg.Accept != nil && !cfg.Accept(ev) {
		b.note("skip", cfg.Name, ev, "not an eligible input", 0, 0)
		_ = msg.Ack()
		return
	}
	// Recheck after pulling; another replica may have just tripped the circuit.
	if _, err := b.Tools.Get(ctx, cfg.Name); err == nil {
		_ = msg.NakWithDelay(cfg.RetryDelay)
		return
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		_ = msg.NakWithDelay(cfg.RetryDelay)
		return
	}
	if err := b.process(ctx, cfg, ev, msg); err != nil {
		slog.Error("work state", "tool", cfg.Name, "err", err)
		// Transport/state outages never clear a claim or reset the execution
		// count. A replacement must acquire its expired lease first.
		_ = msg.NakWithDelay(cfg.RetryDelay)
	}
}
