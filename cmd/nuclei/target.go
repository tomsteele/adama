package main

import (
	"strconv"

	"adama/event"
	"adama/internal/asurl"
)

func target(ev event.Event) (string, bool) {
	if ev.Kind != event.KindService {
		return ev.Value, ev.Value != ""
	}
	name := ev.Service
	if name == "" {
		name = ev.Meta["name"]
	}
	if asurl.IsWeb(name) {
		return "", false
	}
	p := ev.Port
	if p == 0 {
		p, _ = strconv.Atoi(ev.Meta["port"])
	}
	host := ev.Target.Authority()
	if host == "" {
		host = ev.Meta["host"]
	}
	v, err := event.PortValue(host, p)
	if err != nil {
		return "", false
	}
	return v, true
}
