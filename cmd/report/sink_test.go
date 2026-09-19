package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adama/event"
)

func TestDeliverAPI(t *testing.T) {
	var got []byte
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(204)
	}))
	defer s.Close()
	ev := event.Event{Kind: event.KindService, Value: "example.com:443/https"}
	if err := deliver(context.Background(), s.URL, "", ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "example.com:443/https") {
		t.Fatalf("body %s", got)
	}
}

func TestDeliverFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	ev := event.Event{Kind: event.KindScreenshot, Value: "https://example.com"}
	if err := deliver(context.Background(), "", p, ev); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "https://example.com") {
		t.Fatalf("%s %v", b, err)
	}
	html, err := os.ReadFile(filepath.Join(filepath.Dir(p), "report.html"))
	if err != nil || !strings.Contains(string(html), "https://example.com") {
		t.Fatalf("html %s %v", html, err)
	}
}

func TestWriteHTMLScreenshot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	ev := event.Event{Kind: event.KindScreenshot, Value: "https://example.com", Data: []byte("jpeg"), MediaType: "image/jpeg"}
	if err := deliver(context.Background(), "", p, ev); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "data:image/jpeg;base64,") {
		t.Fatalf("missing img: %s", html)
	}
}
