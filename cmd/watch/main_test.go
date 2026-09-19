package main

import (
	"testing"

	"adama/event"
)

func TestApply(t *testing.T) {
	s := newStore()
	s.apply(event.Activity{Action: "start", Tool: "nmap-svc", Kind: event.KindPort, Value: "1.1.1.1:22"})
	s.apply(event.Activity{Action: "start", Tool: "httpx", Kind: event.KindURL, Value: "http://x"})
	if n := len(s.snapshot().Running); n != 2 {
		t.Fatalf("running %d", n)
	}
	s.apply(event.Activity{Action: "done", Tool: "nmap-svc", Kind: event.KindPort, Value: "1.1.1.1:22", Emitted: 1})
	snap := s.snapshot()
	if len(snap.Running) != 1 || snap.Running[0].Tool != "httpx" {
		t.Fatalf("%+v", snap.Running)
	}
	if len(snap.Recent) != 3 || snap.Recent[0].Action != "done" {
		t.Fatalf("recent %+v", snap.Recent)
	}
	s.apply(event.Activity{Action: "skip", Tool: "nuclei", Kind: event.KindURL, Value: "http://x", Reason: "gate"})
	if n := len(s.snapshot().Running); n != 1 {
		t.Fatalf("skip added %d", n)
	}
}
