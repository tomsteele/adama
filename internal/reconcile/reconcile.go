// Package reconcile joins explicit name/address evidence with open endpoints.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"adama/event"
	"adama/sdk"
	"github.com/nats-io/nats.go/jetstream"
)

const Bucket = "ADAMA_FACTS"

type Store struct{ kv jetstream.KeyValue }

func New(ctx context.Context, js jetstream.JetStream) (*Store, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket})
	return &Store{kv: kv}, err
}

func BoundName(ev event.Event) bool {
	return event.BoundName(ev)
}

func InputRule() sdk.Rule {
	return sdk.All(sdk.Not(sdk.FieldIn("source", "reconcile")), sdk.Has("host"),
		sdk.Any(sdk.All(sdk.FieldIn("kind", string(event.KindFQDN)), sdk.BoundNameRule()),
			sdk.All(sdk.FieldIn("kind", string(event.KindPort)), sdk.Has("port"), sdk.FieldIn("proto", string(event.TCP), string(event.UDP)))))
}

func Accept(ev event.Event) bool { return InputRule().Match(ev) }

func digest(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// Handle stores its side before reading the opposite side. The reconcile
// durable uses MaxPending=1; all replicas share that limit. Facts survive both
// worker restarts and an interruption before the output batch is persisted.
func (s *Store) Handle(ctx context.Context, ev event.Event) ([]event.Event, error) {
	if !Accept(ev) {
		return nil, nil
	}
	prefix := digest(ev.Meta["scope"], ev.Host)
	gate := digest(ev.Meta["allow"], ev.Meta["deny"], ev.Meta["profile"])
	var key, opposite string
	switch {
	case ev.Kind == event.KindFQDN && BoundName(ev):
		key = prefix + ".name." + digest(ev.Name) + "." + gate
		opposite = prefix + ".port.>"
	case ev.Kind == event.KindPort && ev.Port > 0 && (ev.Proto == event.TCP || ev.Proto == event.UDP):
		key = fmt.Sprintf("%s.port.%s.%d.%s", prefix, ev.Proto, ev.Port, gate)
		opposite = prefix + ".name.>"
	default:
		return nil, nil
	}
	raw, err := ev.Bytes()
	if err != nil {
		return nil, err
	}
	if _, err := s.kv.Put(ctx, key, raw); err != nil {
		return nil, err
	}
	w, err := s.kv.Watch(ctx, opposite, jetstream.IgnoreDeletes())
	if err != nil {
		return nil, err
	}
	defer w.Stop()
	var out []event.Event
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case entry, ok := <-w.Updates():
			if !ok {
				return out, fmt.Errorf("fact snapshot interrupted")
			}
			if entry == nil {
				return out, nil
			}
			other, err := event.Decode(entry.Value())
			if err != nil {
				return out, err
			}
			name, port := ev, other
			if ev.Kind == event.KindPort {
				name, port = other, ev
			}
			if child, ok := join(name, port); ok {
				out = append(out, child)
			}
		}
	}
}

func join(name, port event.Event) (event.Event, bool) {
	if !BoundName(name) || name.Host != port.Host || name.Meta["scope"] != port.Meta["scope"] {
		return event.Event{}, false
	}
	meta, ok := intersectGates(name.Meta, port.Meta)
	if !ok {
		return event.Event{}, false
	}
	value, err := event.PortValue(name.Name, port.Port)
	if err != nil {
		return event.Event{}, false
	}
	return event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindPort, Value: value,
		Target: event.Target{Host: port.Host, Name: name.Name, NameRole: event.NameRequested, Port: port.Port, Proto: port.Proto},
		Probe:  "name-endpoint-join", Meta: meta, Info: map[string]string{"name_event_id": name.ID, "port_event_id": port.ID}}, true
}

func intersectGates(a, b map[string]string) (map[string]string, bool) {
	aa, ba := event.SplitMetaList(a["allow"]), event.SplitMetaList(b["allow"])
	allow := aa
	if len(aa) == 0 {
		allow = ba
	} else if len(ba) > 0 {
		allow = nil
		for _, tool := range aa {
			if slices.Contains(ba, tool) {
				allow = append(allow, tool)
			}
		}
		if len(allow) == 0 {
			return nil, false
		}
	}
	deny := append(event.SplitMetaList(a["deny"]), event.SplitMetaList(b["deny"])...)
	slices.Sort(deny)
	deny = slices.Compact(deny)
	meta := map[string]string{"scope": a["scope"], "allow": event.JoinMetaList(allow), "deny": event.JoinMetaList(deny)}
	if a["profile"] == b["profile"] {
		meta["profile"] = a["profile"]
	}
	return meta, true
}
