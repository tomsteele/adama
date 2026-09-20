package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adama/event"
)

func TestAppendJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "events.jsonl")
	a := event.Event{Kind: event.KindPort, Value: "192.0.2.1:443", Source: "nmap-quick", ParentID: "parent1"}
	b := event.Event{Kind: event.KindService, Value: "192.0.2.1:443/https", Source: "nmap-svc", ParentID: "parent2"}
	if err := appendJSONL(p, a); err != nil {
		t.Fatal(err)
	}
	if err := appendJSONL(p, b); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines %d: %s", len(lines), raw)
	}
	var gotA, gotB event.Event
	if err := json.Unmarshal([]byte(lines[0]), &gotA); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &gotB); err != nil {
		t.Fatal(err)
	}
	if gotA.Kind != a.Kind || gotA.Value != a.Value || gotA.ParentID != a.ParentID || gotA.Source != a.Source {
		t.Fatalf("first %+v", gotA)
	}
	if gotB.Kind != b.Kind || gotB.Value != b.Value || gotB.ParentID != b.ParentID {
		t.Fatalf("second %+v", gotB)
	}
}

func TestAppendJSONLScreenshot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	ev := event.Event{Kind: event.KindScreenshot, Value: "https://example.com", Data: []byte("jpeg"), MediaType: "image/jpeg"}
	if err := appendJSONL(p, ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `"data":"` + base64.StdEncoding.EncodeToString([]byte("jpeg"))
	if !strings.Contains(string(raw), want) {
		t.Fatalf("missing base64 data: %s", raw)
	}
	var got event.Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "jpeg" || got.MediaType != "image/jpeg" {
		t.Fatalf("got %+v", got)
	}
}

func TestAppendJSONLNoTruncate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(p, []byte("{\"kind\":\"ip\",\"value\":\"192.0.2.1\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{Kind: event.KindDomain, Value: "example.com"}
	if err := appendJSONL(p, ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "192.0.2.1") || !strings.Contains(string(raw), "example.com") {
		t.Fatalf("truncated? %s", raw)
	}
}
