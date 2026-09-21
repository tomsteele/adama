// Package coverage reconstructs desired work from retained observations and
// compares it with durable execution state. It never claims or retries work.
package coverage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"adama/event"
	"adama/sdk"
	"github.com/nats-io/nats.go/jetstream"
)

type Filter struct {
	Run   string `json:"run,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type Item struct {
	Key       string       `json:"key"`
	Tool      string       `json:"tool"`
	EventID   string       `json:"event_id"`
	RunID     string       `json:"run_id,omitempty"`
	Scope     string       `json:"scope,omitempty"`
	Input     *event.Input `json:"input"`
	Status    string       `json:"status"`
	TaskRunID string       `json:"task_run_id,omitempty"`
	Attempts  int          `json:"attempts"`
	Emitted   int          `json:"emitted"`
	Error     string       `json:"error,omitempty"`
}

type Worker struct {
	Tool           string `json:"tool"`
	ConsumerExists bool   `json:"consumer_exists"`
	Pending        uint64 `json:"pending"`
	AckPending     int    `json:"ack_pending"`
	Paused         bool   `json:"paused"`
}

type Report struct {
	Filter           Filter         `json:"filter"`
	At               time.Time      `json:"at"`
	ThroughSequence  uint64         `json:"through_sequence"`
	RegistrySequence uint64         `json:"registry_sequence"`
	Inventory        *sdk.Inventory `json:"inventory,omitempty"`
	MatchedEvents    int            `json:"matched_events"`
	SharedScopes     []string       `json:"shared_scopes"`
	Stable           bool           `json:"snapshot_stable"`
	Complete         bool           `json:"work_complete_at_snapshot"`
	Counts           map[string]int `json:"counts"`
	Warnings         []string       `json:"warnings,omitempty"`
	Workers          []Worker       `json:"workers"`
	Items            []Item         `json:"items"`
}

type expectation struct {
	tool    sdk.Definition
	ev      event.Event
	blocked string
}

type planner struct {
	tools   []sdk.Definition
	ready   map[string]expectation
	blocked map[string]expectation
	live    map[string]bool
	bound   map[string]bool
	unknown map[string]bool
}

func newPlanner(tools []sdk.Definition) *planner {
	return &planner{tools: tools, ready: map[string]expectation{}, blocked: map[string]expectation{}, live: map[string]bool{}, bound: map[string]bool{}, unknown: map[string]bool{}}
}

func identity(parts ...any) string {
	raw, _ := json.Marshal(parts)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func prerequisite(tool string, ev event.Event) string {
	return identity(tool, ev.Meta["scope"], ev.Kind, ev.Value, ev.Host)
}
func binding(tool string, ev event.Event) string { return identity(tool, ev.Meta["scope"], ev.Name) }

func (p *planner) add(ev event.Event) {
	for _, name := range event.SplitMetaList(ev.Meta["allow"]) {
		if !slices.ContainsFunc(p.tools, func(t sdk.Definition) bool { return t.Name == name }) {
			p.unknown[name] = true
		}
	}
	for _, tool := range p.tools {
		if tool.NeedBinding && ev.Kind == event.KindFQDN && slices.Contains(tool.Kinds, ev.Kind) && event.Allowed(tool.Name, ev.Meta) {
			if event.BoundName(ev) {
				p.bound[binding(tool.Name, ev)] = true
			} else if tool.Matches(ev) {
				p.blocked[prerequisite(tool.Name, ev)] = expectation{tool: tool, ev: ev, blocked: "blocked_resolution"}
				continue
			}
		}
		if !tool.Matches(ev) {
			continue
		}
		if tool.NeedLive {
			if ev.Kind == event.KindFQDN && event.BoundName(ev) {
				p.bound[binding(tool.Name, ev)] = true
			}
			key := prerequisite(tool.Name, ev)
			if !event.Live(ev) {
				reason := "blocked_liveness"
				if ev.Kind == event.KindFQDN && !event.BoundName(ev) {
					reason = "blocked_resolution"
				}
				p.blocked[key] = expectation{tool: tool, ev: ev, blocked: reason}
				continue
			}
			p.live[key] = true
		}
		p.ready[sdk.WorkKey(tool.Config(), ev)] = expectation{tool: tool, ev: ev}
	}
	// A domain includes its apex even when enumeration/resolution yielded no
	// children. This exposes the missing prerequisite rather than an empty run.
	if ev.Kind == event.KindDomain {
		apex := ev
		apex.Kind = event.KindFQDN
		apex.Target = event.Target{Name: ev.Value}
		for _, tool := range p.tools {
			if (tool.NeedLive || tool.NeedBinding) && tool.Matches(apex) {
				p.blocked[prerequisite(tool.Name, apex)] = expectation{tool: tool, ev: apex, blocked: "blocked_resolution"}
			}
		}
	}
}

func (p *planner) expectations() map[string]expectation {
	out := make(map[string]expectation, len(p.ready)+len(p.blocked))
	for k, v := range p.ready {
		out[k] = v
	}
	for k, v := range p.blocked {
		if p.live[k] {
			continue
		}
		if v.blocked == "blocked_resolution" && p.bound[binding(v.tool.Name, v.ev)] {
			continue
		}
		out["prerequisite/"+k] = v
	}
	return out
}

// Snapshot reads a fixed EVENTS boundary, then checks that neither the event
// history nor the work ledger changed during the read. New inputs can always
// extend a run later; complete is explicitly qualified by this boundary.
func Snapshot(ctx context.Context, b *sdk.Bus, filter Filter) (Report, error) {
	r := Report{Filter: filter, At: time.Now().UTC(), Counts: map[string]int{}}
	if filter.Run == "" && filter.Scope == "" {
		return r, fmt.Errorf("coverage requires --run or --scope")
	}
	registryStream, err := b.JS.Stream(ctx, "KV_"+sdk.RegistryBucket)
	if err != nil {
		return r, err
	}
	registryStart, err := registryStream.Info(ctx)
	if err != nil {
		return r, err
	}
	r.RegistrySequence = registryStart.State.LastSeq
	registrations, err := b.Registrations(ctx)
	if err != nil {
		return r, err
	}
	var tools []sdk.Definition
	for _, registration := range registrations {
		tools = append(tools, registration.Definition)
	}
	if len(tools) == 0 {
		r.Warnings = append(r.Warnings, "no workers have registered")
	}
	inventory, err := b.Inventory(ctx)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		r.Warnings = append(r.Warnings, "worker inventory has not been recorded; register the deployment before certifying coverage")
	} else if err != nil {
		return r, err
	} else {
		r.Inventory = &inventory
		if !inventory.Ready {
			r.Warnings = append(r.Warnings, "worker inventory registration is incomplete")
		}
		for _, name := range inventory.Workers {
			if !slices.ContainsFunc(tools, func(tool sdk.Definition) bool { return tool.Name == name }) {
				r.Warnings = append(r.Warnings, "expected worker has not registered: "+name)
			}
		}
	}
	stream, err := b.JS.Stream(ctx, sdk.StreamName)
	if err != nil {
		return r, err
	}
	start, err := stream.Info(ctx)
	if err != nil {
		return r, err
	}
	workStream, err := b.JS.Stream(ctx, "KV_"+sdk.WorkBucket)
	if err != nil {
		return r, err
	}
	workStart, err := workStream.Info(ctx)
	if err != nil {
		return r, err
	}
	r.ThroughSequence = start.State.LastSeq
	if start.State.FirstSeq > 1 || start.State.NumDeleted > 0 {
		r.Warnings = append(r.Warnings, "event history has been removed; coverage may omit earlier inputs")
	}
	p := newPlanner(tools)
	// Task identity is scope-based, not run-based. Include evidence from other
	// runs sharing the selected scopes, or reused tasks could look complete
	// while their previously emitted downstream work is omitted.
	var observations []event.Event
	scopes := map[string]bool{}
	for seq := max(uint64(1), start.State.FirstSeq); seq <= start.State.LastSeq; seq++ {
		msg, err := stream.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("event sequence %d is no longer retained", seq))
			continue
		}
		if err != nil {
			return r, err
		}
		ev, err := event.Decode(msg.Data)
		if err == nil {
			ev, err = ev.Canonical()
		}
		if err != nil {
			return r, fmt.Errorf("event sequence %d: %w", seq, err)
		}
		if ev.ID == "" {
			ev.ID = fmt.Sprintf("legacy-%s-%d", sdk.StreamName, seq)
		}
		if ev.RunID == "" && ev.ParentID == "" {
			ev.RunID = ev.ID
		}
		if filter.Scope != "" && ev.Meta["scope"] != filter.Scope {
			continue
		}
		if filter.Run == "" || ev.RunID == filter.Run {
			scopes[ev.Meta["scope"]] = true
		}
		ev.Data, ev.Info = nil, nil // Artifacts are not needed to plan work.
		observations = append(observations, ev)
	}
	for _, ev := range observations {
		if !scopes[ev.Meta["scope"]] {
			continue
		}
		r.MatchedEvents++
		p.add(ev)
	}
	for scope := range scopes {
		r.SharedScopes = append(r.SharedScopes, scope)
	}
	sort.Strings(r.SharedScopes)
	if r.MatchedEvents == 0 {
		r.Warnings = append(r.Warnings, "no retained observations match this selection")
	}
	for name := range p.unknown {
		r.Warnings = append(r.Warnings, "allowlist names a worker that has not registered: "+name)
	}
	for key, expected := range p.expectations() {
		ev := expected.ev
		item := Item{Key: key, Tool: expected.tool.Name, EventID: ev.ID, RunID: ev.RunID, Scope: ev.Meta["scope"], Input: ev.AsInput(), Status: expected.blocked}
		if item.Status == "" {
			item.Status = "unclaimed"
			entry, err := b.KV.Get(ctx, key)
			if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
				return r, err
			}
			if err == nil {
				var task sdk.Task
				if err := json.Unmarshal(entry.Value(), &task); err != nil {
					return r, fmt.Errorf("work state %s: %w", key, err)
				}
				item.Status, item.TaskRunID, item.Attempts, item.Emitted, item.Error = task.Status, task.RunID, task.Attempts, task.Emitted, task.Error
				if task.Status == sdk.TaskCompleted && task.Emitted == 0 && expected.tool.Evidence != "" {
					item.Status, item.Error = "completed_without_evidence", "successful execution produced no "+expected.tool.Evidence
				}
				if (task.Status == sdk.TaskRunning || task.Status == sdk.TaskPublishing) && !task.LeaseUntil.After(r.At) {
					item.Status = "lease_expired"
				}
			}
		}
		r.Counts[item.Status]++
		r.Items = append(r.Items, item)
	}
	for _, tool := range tools {
		w := Worker{Tool: tool.Name}
		consumer, err := b.JS.Consumer(ctx, sdk.StreamName, tool.Name)
		if err == nil {
			info, err := consumer.Info(ctx)
			if err != nil {
				return r, err
			}
			w.ConsumerExists, w.Pending, w.AckPending = true, info.NumPending, info.NumAckPending
		} else if !errors.Is(err, jetstream.ErrConsumerNotFound) {
			return r, err
		}
		_, err = b.Tools.Get(ctx, tool.Name)
		if err == nil {
			w.Paused = true
		} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
			return r, err
		}
		r.Workers = append(r.Workers, w)
	}
	end, err := stream.Info(ctx)
	if err != nil {
		return r, err
	}
	workEnd, err := workStream.Info(ctx)
	if err != nil {
		return r, err
	}
	registryEnd, err := registryStream.Info(ctx)
	if err != nil {
		return r, err
	}
	r.Stable = start.State.LastSeq == end.State.LastSeq && start.State.FirstSeq == end.State.FirstSeq && start.State.Msgs == end.State.Msgs && workStart.State.LastSeq == workEnd.State.LastSeq && registryStart.State.LastSeq == registryEnd.State.LastSeq
	if !r.Stable {
		r.Warnings = append(r.Warnings, "events, work state, or registrations changed during the snapshot; run coverage again")
	}
	r.Complete = r.Stable && len(r.Warnings) == 0 && len(r.Items) > 0 && r.Counts[sdk.TaskCompleted] == len(r.Items)
	sort.Slice(r.Items, func(i, j int) bool {
		if r.Items[i].Tool != r.Items[j].Tool {
			return r.Items[i].Tool < r.Items[j].Tool
		}
		return r.Items[i].Key < r.Items[j].Key
	})
	sort.Slice(r.Workers, func(i, j int) bool { return r.Workers[i].Tool < r.Workers[j].Tool })
	sort.Strings(r.Warnings)
	return r, nil
}
