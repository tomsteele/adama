package main

import (
	"testing"

	"adama/event"
)

func TestParseHostnames(t *testing.T) {
	raw := []byte(`["WWW.Example.COM","www.example.com","*.dev.example.com","other.com","mail.example.com"]`)
	got := parseHostnames(raw, "Example.COM")
	want := map[string]bool{"www.example.com": true, "mail.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for _, ev := range got {
		if ev.Kind != event.KindFQDN || ev.Meta["via"] != "ctl" || ev.Meta["parent"] != "example.com" {
			t.Fatalf("%+v", ev)
		}
		if !want[ev.Value] {
			t.Fatalf("extra %q", ev.Value)
		}
	}
}
