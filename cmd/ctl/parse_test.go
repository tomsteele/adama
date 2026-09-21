package main

import (
	"testing"

	"adama/event"
)

func TestParseHostnames(t *testing.T) {
	raw := []byte(`["WWW.Example.COM","www.example.com","*.dev.example.com","other.com","mail.example.com"]`)
	got, err := parseHostnames(raw, "Example.COM")
	if err != nil {
		t.Fatal(err)
	}
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

func TestKeepResolved(t *testing.T) {
	in, err := parseHostnames([]byte(`["www.example.com","dead.example.com"]`), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := keepResolved(in, []byte(`{"host":"www.example.com","a":["1.2.3.4"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != "www.example.com" {
		t.Fatalf("%+v", got)
	}
	if got[0].Host != "1.2.3.4" || got[0].NameRole != event.NameDNSA {
		t.Fatalf("missing DNS relationship: %+v", got[0])
	}
}
