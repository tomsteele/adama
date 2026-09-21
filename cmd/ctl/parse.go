package main

import (
	"encoding/json"
	"strings"

	"adama/event"
	"adama/internal/dnsresult"
)

func parseHostnames(body []byte, domain string) []event.Event {
	var names []string
	if json.Unmarshal(body, &names) != nil {
		return nil
	}
	domain = event.CanonFQDN(domain)
	suffix := "." + domain
	seen := map[string]bool{}
	var evs []event.Event
	for _, raw := range names {
		name := event.CanonFQDN(raw)
		if name == "" || strings.Contains(name, "*") {
			continue
		}
		if name != domain && !strings.HasSuffix(name, suffix) {
			continue
		}
		if _, err := event.CanonIP(name); err == nil {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		evs = append(evs, event.Event{
			SchemaVersion: event.SchemaVersion,
			Kind:          event.KindFQDN,
			Value:         name,
			Target:        event.Target{Name: name, NameRole: event.NameCT},
			Probe:         "certificate-transparency",
			Meta:          map[string]string{"parent": domain, "via": "ctl"},
		})
	}
	return evs
}

func keepResolved(evs []event.Event, stdout []byte) ([]event.Event, error) {
	resolved, err := dnsresult.Parse(stdout, "ctl", "")
	if err != nil {
		return nil, err
	}
	names := map[string]event.Event{}
	for _, ev := range evs {
		names[ev.Value] = ev
	}
	var out []event.Event
	for _, ev := range resolved {
		if original, ok := names[ev.Value]; ok {
			ev.Meta["parent"] = original.Meta["parent"]
			ev.Info["parent"] = original.Meta["parent"]
			ev.Info["discovery"] = "certificate_transparency"
			out = append(out, ev)
		}
	}
	return out, nil
}
