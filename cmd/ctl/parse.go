package main

import (
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
