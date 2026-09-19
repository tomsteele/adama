package main

import (
	"os"
	"path/filepath"
	"testing"

	"adama/event"
)

func TestGowitnessFile(t *testing.T) {
	got := gowitnessFile("screenshots", "https://console.nscale.com")
	if got != filepath.Join("screenshots", "https---console.nscale.com.jpeg") {
		t.Fatal(got)
	}
}

func TestAttachShot(t *testing.T) {
	dir := t.TempDir()
	u := "https://example.com"
	p := gowitnessFile(dir, u)
	if err := os.WriteFile(p, []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{Kind: event.KindScreenshot, Value: u}
	attachShot(dir, u, &ev)
	if string(ev.Data) != "jpeg" || ev.MediaType != "image/jpeg" {
		t.Fatalf("%+v", ev)
	}
}
