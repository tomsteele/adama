package sdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"adama/event"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"
)

const (
	StreamName  = "EVENTS"
	DedupBucket = WorkBucket
)

func NATSURL() string {
	if u := os.Getenv("NATS_URL"); u != "" {
		return u
	}
	return "nats://127.0.0.1:4222"
}

type Bus struct {
	nc     *nats.Conn
	JS     jetstream.JetStream
	KV     jetstream.KeyValue
	Outbox jetstream.ObjectStore
	Tools  jetstream.KeyValue
}

func Connect(ctx context.Context, url string) (*Bus, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       StreamName,
		Subjects:   []string{event.SubjectPrefix + ">"},
		MaxMsgSize: 8 << 20,
		Retention:  jetstream.LimitsPolicy,
		Storage:    jetstream.FileStorage,
	}); err != nil {
		nc.Close()
		return nil, err
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: DedupBucket,
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	outbox, err := js.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: OutboxBucket, Storage: jetstream.FileStorage})
	if err != nil {
		nc.Close()
		return nil, err
	}
	toolState, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: ToolBucket})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &Bus{nc: nc, JS: js, KV: kv, Outbox: outbox, Tools: toolState}, nil
}

func (b *Bus) Close() { b.nc.Close() }

func (b *Bus) Publish(ctx context.Context, ev event.Event) error {
	ev, err := prepare(ev)
	if err != nil {
		return err
	}
	raw, err := ev.Bytes()
	if err != nil {
		return err
	}
	_, err = b.JS.Publish(ctx, event.Subject(ev.Kind), raw, jetstream.WithMsgID(ev.ID))
	return err
}

func prepare(ev event.Event) (event.Event, error) {
	ev, err := ev.Canonical()
	if err != nil {
		return ev, err
	}
	if ev.ID == "" {
		ev.ID = nuid.Next()
	}
	if ev.RunID == "" && ev.ParentID == "" {
		ev.RunID = ev.ID
	}
	if ev.Observed.IsZero() {
		ev.Observed = time.Now().UTC()
	}
	raw, err := ev.Bytes()
	if err == nil && len(raw) > 8<<20 {
		err = fmt.Errorf("event exceeds 8 MiB payload limit")
	}
	return ev, err
}

type Config struct {
	Name               string
	URL                string
	Kinds              []event.Kind
	AckWait            time.Duration
	NeedLive           bool                   // skip before dedup unless meta.alive=true
	Observe            bool                   // observation sinks receive every event; redelivery retains its ID
	RequiredTools      []string               // fail before consuming targets if a binary is missing
	Accept             func(event.Event) bool // pure eligibility check, before claiming work
	MaxAttempts        int
	MaxPublishAttempts int
	MaxPending         int
	TaskTimeout        time.Duration
	RetryWindow        time.Duration
	RetryDelay         time.Duration
	LeaseDuration      time.Duration
	ShutdownGrace      time.Duration
	Handle             func(context.Context, event.Event) ([]event.Event, error)
}

func Run(ctx context.Context, cfg Config) error {
	var err error
	cfg, err = cfg.defaults()
	if err != nil {
		return err
	}
	if cfg.Name == "" || cfg.Handle == nil {
		return fmt.Errorf("worker needs name and handler")
	}
	for _, binary := range cfg.RequiredTools {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Errorf("worker %s prerequisite: %w", cfg.Name, err)
		}
	}
	if cfg.URL == "" {
		cfg.URL = NATSURL()
	}
	b, err := Connect(ctx, cfg.URL)
	if err != nil {
		return err
	}
	defer b.Close()
	cons, err := b.consumer(ctx, cfg)
	if err != nil {
		return err
	}
	messages, err := cons.Messages(jetstream.PullMaxMessages(1))
	if err != nil {
		return err
	}
	defer messages.Stop()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			messages.Stop()
		case <-stopped:
		}
	}()
	slog.Info("listening", "tool", cfg.Name, "kinds", cfg.Kinds)
	for ctx.Err() == nil {
		if _, err := b.Tools.Get(ctx, cfg.Name); err == nil {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
			return err
		}
		msg, err := messages.Next()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			_ = msg.NakWithDelay(cfg.RetryDelay)
			break
		}
		b.onMsg(ctx, cfg, msg)
	}
	return nil
}

func (b *Bus) consumer(ctx context.Context, cfg Config) (jetstream.Consumer, error) {
	subjects := make([]string, len(cfg.Kinds))
	for i, k := range cfg.Kinds {
		subjects[i] = event.Subject(k)
	}
	wanted := jetstream.ConsumerConfig{
		Durable: cfg.Name, FilterSubjects: subjects, AckPolicy: jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy, AckWait: cfg.AckWait,
		MaxDeliver: -1, MaxAckPending: cfg.MaxPending,
	}
	cons, err := b.JS.CreateConsumer(ctx, StreamName, wanted)
	if err != nil && !consumerExists(err) {
		return nil, err
	}
	if cons == nil {
		cons, err = b.JS.Consumer(ctx, StreamName, cfg.Name)
		if err != nil {
			return nil, err
		}
	}
	info, err := cons.Info(ctx)
	if err != nil {
		return nil, err
	}
	got := info.Config
	filters := append([]string{}, got.FilterSubjects...)
	if got.FilterSubject != "" {
		filters = append(filters, got.FilterSubject)
	}
	slices.Sort(filters)
	slices.Sort(subjects)
	if !slices.Equal(filters, subjects) || got.AckPolicy != wanted.AckPolicy || got.DeliverPolicy != wanted.DeliverPolicy || got.AckWait != wanted.AckWait || got.MaxDeliver != wanted.MaxDeliver || got.MaxAckPending != wanted.MaxAckPending {
		return nil, fmt.Errorf("consumer %s configuration differs from worker; migrate the durable explicitly before starting (filters, delivery policy, AckWait, MaxDeliver, MaxAckPending)", cfg.Name)
	}
	return cons, nil
}

func consumerExists(err error) bool {
	return errors.Is(err, jetstream.ErrConsumerExists) ||
		errors.Is(err, jetstream.ErrConsumerNameAlreadyInUse) ||
		strings.Contains(err.Error(), "already in use") ||
		strings.Contains(err.Error(), "already exists")
}

func (b *Bus) note(action, tool string, ev event.Event, reason string, emitted int, elapsed time.Duration) {
	a := event.Activity{
		Action:  action,
		Tool:    tool,
		Kind:    ev.Kind,
		Value:   ev.Value,
		Reason:  reason,
		Emitted: emitted,
		At:      time.Now().UTC(),
	}
	if ev.Meta != nil {
		a.Scope = ev.Meta["scope"]
	}
	if elapsed > 0 {
		a.Elapsed = elapsed.Round(time.Millisecond).String()
	}
	raw, err := a.Bytes()
	if err != nil {
		return
	}
	_ = b.nc.Publish(event.ActivitySubject, raw)
}

func Seed(ctx context.Context, url string, ev event.Event) error {
	if url == "" {
		url = NATSURL()
	}
	b, err := Connect(ctx, url)
	if err != nil {
		return err
	}
	defer b.Close()
	if ev.Source == "" {
		ev.Source = "seed"
	}
	return b.Publish(ctx, ev)
}
