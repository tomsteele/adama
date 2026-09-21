package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"adama/event"
	"github.com/nats-io/nats.go/jetstream"
)

const RegistryBucket = "ADAMA_REGISTRY"
const DefinitionVersion = 1

// Definition is the worker's execution contract, published by sdk.Run before
// consuming work. It has no lease or TTL: absent workers remain expected.
type Definition struct {
	Version     int          `json:"version"`
	Name        string       `json:"name"`
	Kinds       []event.Kind `json:"kinds"`
	NeedLive    bool         `json:"need_live,omitempty"`
	NeedBinding bool         `json:"need_binding,omitempty"`
	Observe     bool         `json:"observe,omitempty"`
	Filter      Rule         `json:"filter"`
	Evidence    string       `json:"evidence,omitempty"`
}

type Registration struct {
	Definition  Definition `json:"definition"`
	Fingerprint string     `json:"fingerprint"`
	Registered  time.Time  `json:"registered_at"`
}

// Inventory is a deployment-generated expectation, independent of whether the
// corresponding worker has ever consumed a message. Incomplete provisioning
// must not leave the previous deployment looking complete.
type Inventory struct {
	Version int       `json:"version"`
	Ready   bool      `json:"ready"`
	Workers []string  `json:"workers"`
	Updated time.Time `json:"updated_at"`
}

func (c Config) Definition() Definition {
	kinds := append([]event.Kind{}, c.Kinds...)
	slices.Sort(kinds)
	kinds = slices.Compact(kinds)
	return Definition{Version: DefinitionVersion, Name: c.Name, Kinds: kinds, NeedLive: c.NeedLive, NeedBinding: c.NeedBinding, Observe: c.Observe, Filter: c.Filter, Evidence: c.Evidence}
}

func (d Definition) Config() Config {
	return Config{Name: d.Name, Kinds: d.Kinds, NeedLive: d.NeedLive, NeedBinding: d.NeedBinding, Observe: d.Observe, Filter: d.Filter, Evidence: d.Evidence}
}

// Matches excludes prerequisites so coverage can retain them as blockers.
func (d Definition) Matches(ev event.Event) bool {
	return slices.Contains(d.Kinds, ev.Kind) && event.Allowed(d.Name, ev.Meta) && d.Filter.Match(ev)
}

func (d Definition) Eligible(ev event.Event) bool {
	return d.Matches(ev) && (!d.NeedLive || event.Live(ev)) &&
		(!d.NeedBinding || ev.Kind != event.KindFQDN || event.BoundName(ev))
}

var workerName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (d Definition) Validate() error {
	if d.Version != DefinitionVersion {
		return fmt.Errorf("unsupported worker definition version %d", d.Version)
	}
	if !workerName.MatchString(d.Name) || len(d.Kinds) == 0 {
		return fmt.Errorf("worker definition needs a valid name and kinds")
	}
	for _, kind := range d.Kinds {
		switch kind {
		case event.KindDomain, event.KindFQDN, event.KindNetblock, event.KindIP, event.KindPort, event.KindService, event.KindURL, event.KindScreenshot, event.KindFinding:
		default:
			return fmt.Errorf("worker %s: unknown kind %q", d.Name, kind)
		}
	}
	return d.Filter.Validate()
}

func (d Definition) Fingerprint() string {
	raw, _ := json.Marshal(d)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// Register is idempotent for replicas with the same contract. A different
// contract under the same durable name is an error, never last-writer-wins.
// Replacement is an explicit provisioning operation after stopping replicas.
func (b *Bus) Register(ctx context.Context, definition Definition, replace bool) (Registration, error) {
	if err := definition.Validate(); err != nil {
		return Registration{}, err
	}
	definition = definition.Config().Definition()
	r := Registration{Definition: definition, Fingerprint: definition.Fingerprint(), Registered: time.Now().UTC()}
	raw, _ := json.Marshal(r)
	key := "worker." + definition.Name
	_, err := b.Registry.Create(ctx, key, raw)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, jetstream.ErrKeyExists) {
		return Registration{}, err
	}
	entry, err := b.Registry.Get(ctx, key)
	if err != nil {
		return Registration{}, err
	}
	var old Registration
	if err := json.Unmarshal(entry.Value(), &old); err != nil {
		return Registration{}, err
	}
	if old.Fingerprint == r.Fingerprint {
		return old, nil
	}
	if !replace {
		return Registration{}, fmt.Errorf("worker %s registration differs; stop its replicas and explicitly replace the registration before restarting", definition.Name)
	}
	if _, err := b.Registry.Update(ctx, key, raw, entry.Revision()); err != nil {
		return Registration{}, err
	}
	return r, nil
}

func (b *Bus) Registrations(ctx context.Context) ([]Registration, error) {
	w, err := b.Registry.Watch(ctx, "worker.*", jetstream.IgnoreDeletes())
	if err != nil {
		return nil, err
	}
	defer w.Stop()
	var out []Registration
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case entry, ok := <-w.Updates():
			if !ok {
				return nil, fmt.Errorf("worker registry snapshot interrupted")
			}
			if entry == nil {
				sort.Slice(out, func(i, j int) bool { return out[i].Definition.Name < out[j].Definition.Name })
				return out, nil
			}
			var r Registration
			if err := json.Unmarshal(entry.Value(), &r); err != nil {
				return nil, err
			}
			if err := r.Definition.Validate(); err != nil {
				return nil, err
			}
			if r.Fingerprint != r.Definition.Fingerprint() {
				return nil, fmt.Errorf("invalid registration fingerprint for %s", r.Definition.Name)
			}
			out = append(out, r)
		}
	}
}

func (b *Bus) Inventory(ctx context.Context) (Inventory, error) {
	entry, err := b.Registry.Get(ctx, "inventory")
	if err != nil {
		return Inventory{}, err
	}
	var inv Inventory
	if err := json.Unmarshal(entry.Value(), &inv); err != nil {
		return inv, err
	}
	if inv.Version != DefinitionVersion {
		return inv, fmt.Errorf("unsupported inventory version %d", inv.Version)
	}
	return inv, nil
}

func (b *Bus) SetInventory(ctx context.Context, names []string, ready bool) error {
	for _, name := range names {
		if !workerName.MatchString(name) {
			return fmt.Errorf("invalid inventory worker %q", name)
		}
	}
	names = append([]string{}, names...)
	slices.Sort(names)
	names = slices.Compact(names)
	if ready && len(names) == 0 {
		return fmt.Errorf("worker inventory must not be empty")
	}
	raw, _ := json.Marshal(Inventory{Version: DefinitionVersion, Ready: ready, Workers: names, Updated: time.Now().UTC()})
	_, err := b.Registry.Put(ctx, "inventory", raw)
	return err
}
