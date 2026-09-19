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
	if asurl.IsWeb(ev.Meta["name"]) {
		return "", false
	}
	p, err := strconv.Atoi(ev.Meta["port"])
	if err != nil {
		return "", false
	}
	v, err := event.PortValue(ev.Meta["host"], p)
	if err != nil {
		return "", false
	}
	return v, true
}
