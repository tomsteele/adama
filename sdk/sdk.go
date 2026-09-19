package sdk

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"adama/event"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"
)

const (
	StreamName  = "EVENTS"
	DedupBucket = "ADAMA_DEDUP"
	DefaultTTL  = 24 * time.Hour
)

func NATSURL() string {
	if u := os.Getenv("NATS_URL"); u != "" {
		return u
	}
	return "nats://127.0.0.1:4222"
}

type Bus struct {
	nc *nats.Conn
	JS jetstream.JetStream
	KV jetstream.KeyValue
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
		MaxAge:     DefaultTTL,
		MaxMsgSize: 8 << 20,
		Retention:  jetstream.LimitsPolicy,
		Storage:    jetstream.FileStorage,
	}); err != nil {
		nc.Close()
		return nil, err
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: DedupBucket,
		TTL:    DefaultTTL,
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &Bus{nc: nc, JS: js, KV: kv}, nil
}

func (b *Bus) Close() { b.nc.Close() }

func (b *Bus) Publish(ctx context.Context, ev event.Event) error {
	ev, err := ev.Canonical()
	if err != nil {
		return err
	}
	if ev.ID == "" {
		ev.ID = nuid.Next()
	}
	if ev.Observed.IsZero() {
		ev.Observed = time.Now().UTC()
	}
	raw, err := ev.Bytes()
	if err != nil {
		return err
	}
	_, err = b.JS.Publish(ctx, event.Subject(ev.Kind), raw)
	return err
}

type Config struct {
	Name     string
	URL      string
	Kinds    []event.Kind
	AckWait  time.Duration
	NeedLive bool // skip before dedup unless meta.alive=true
	Handle   func(context.Context, event.Event) ([]event.Event, error)
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.URL == "" {
		cfg.URL = NATSURL()
	}
	b, err := Connect(ctx, cfg.URL)
	if err != nil {
		return err
	}
	defer b.Close()

	subjects := make([]string, len(cfg.Kinds))
	for i, k := range cfg.Kinds {
		subjects[i] = event.Subject(k)
	}
	ackWait := cfg.AckWait
	if ackWait == 0 {
		ackWait = 5 * time.Minute
	}
	_, err = b.JS.CreateConsumer(ctx, StreamName, jetstream.ConsumerConfig{
		Durable:        cfg.Name,
		FilterSubjects: subjects,
		AckPolicy:      jetstream.AckExplicitPolicy,
		DeliverPolicy:  jetstream.DeliverNewPolicy,
		AckWait:        ackWait,
		MaxDeliver:     5,
		MaxAckPending:  1,
	})
	if err != nil && !consumerExists(err) {
		return err
	}
	cons, err := b.JS.Consumer(ctx, StreamName, cfg.Name)
	if err != nil {
		return err
	}

	slog.Info("listening", "tool", cfg.Name, "kinds", cfg.Kinds)
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		b.onMsg(ctx, cfg, msg)
	})
	if err != nil {
		return err
	}
	defer cc.Stop()
	<-ctx.Done()
	return nil
}

func consumerExists(err error) bool {
	return errors.Is(err, jetstream.ErrConsumerExists) ||
		errors.Is(err, jetstream.ErrConsumerNameAlreadyInUse) ||
		strings.Contains(err.Error(), "already in use") ||
		strings.Contains(err.Error(), "already exists")
}

func (b *Bus) onMsg(ctx context.Context, cfg Config, msg jetstream.Msg) {
	ev, err := event.Decode(msg.Data())
	if err != nil {
		slog.Error("decode", "err", err)
		_ = msg.Ack()
		return
	}
	ev, err = ev.Canonical()
	if err != nil {
		slog.Error("canon", "err", err, "kind", ev.Kind, "value", ev.Value)
		_ = msg.Ack()
		return
	}
	if !event.Allowed(cfg.Name, ev.Meta) {
		slog.Info("skip", "tool", cfg.Name, "kind", ev.Kind, "value", ev.Value, "reason", "gate")
		b.note("skip", cfg.Name, ev, "gate", 0, 0)
		_ = msg.Ack()
		return
	}
	if cfg.NeedLive && !event.Live(ev) {
		slog.Info("skip", "tool", cfg.Name, "kind", ev.Kind, "value", ev.Value, "reason", "alive")
		b.note("skip", cfg.Name, ev, "alive", 0, 0)
		_ = msg.Ack()
		return
	}
	key := event.DedupKey(cfg.Name, ev)
	if _, err := b.KV.Create(ctx, key, []byte("1")); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			slog.Info("skip", "tool", cfg.Name, "kind", ev.Kind, "value", ev.Value)
			b.note("skip", cfg.Name, ev, "dedup", 0, 0)
			_ = msg.Ack()
			return
		}
		slog.Error("dedup", "err", err)
		_ = msg.Nak()
		return
	}

	slog.Info("handle", "tool", cfg.Name, "kind", ev.Kind, "value", ev.Value)
	t0 := time.Now()
	b.note("start", cfg.Name, ev, "", 0, 0)
	out, err := cfg.Handle(ctx, ev)
	if err != nil {
		slog.Error("handle", "tool", cfg.Name, "err", err)
		b.note("error", cfg.Name, ev, err.Error(), 0, time.Since(t0))
		_ = b.KV.Delete(ctx, key)
		_ = msg.Nak()
		return
	}
	for _, child := range out {
		child.Source = cfg.Name
		child.ParentID = ev.ID
		child = event.InheritGate(ev, child)
		if err := b.Publish(ctx, child); err != nil {
			slog.Error("publish", "err", err, "kind", child.Kind, "value", child.Value)
			b.note("error", cfg.Name, ev, err.Error(), 0, time.Since(t0))
			_ = b.KV.Delete(ctx, key)
			_ = msg.Nak()
			return
		}
		slog.Info("emit", "tool", cfg.Name, "kind", child.Kind, "value", child.Value)
	}
	b.note("done", cfg.Name, ev, "", len(out), time.Since(t0))
	_ = msg.Ack()
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
