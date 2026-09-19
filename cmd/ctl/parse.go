package main

import (
	"bytes"
	"encoding/json"
	"strings"

	"adama/event"
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
			Kind:  event.KindFQDN,
			Value: name,
			Meta:  map[string]string{"parent": domain, "via": "ctl"},
		})
	}
	return evs
}

func keepResolved(evs []event.Event, stdout []byte) []event.Event {
	live := map[string]bool{}
	for _, line := range bytes.Split(stdout, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if i := strings.IndexAny(s, " \t["); i > 0 {
			s = s[:i]
		}
		if n := event.CanonFQDN(s); n != "" {
			live[n] = true
		}
	}
	var out []event.Event
	for _, ev := range evs {
		if live[ev.Value] {
			out = append(out, ev)
		}
	}
	return out
}
