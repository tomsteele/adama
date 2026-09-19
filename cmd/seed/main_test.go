package main

import (
	"testing"

	"adama/event"
)

func TestParseArgs(t *testing.T) {
	k, v, err := parseArgs([]string{"192.168.1.1:22"})
	if err != nil || k != event.KindPort || v != "192.168.1.1:22" {
		t.Fatalf("%s %s %v", k, v, err)
	}
	k, v, err = parseArgs([]string{"ip", "192.168.1.1"})
	if err != nil || k != event.KindIP || v != "192.168.1.1" {
		t.Fatalf("%s %s %v", k, v, err)
	}
	if _, _, err := parseArgs(nil); err == nil {
		t.Fatal("want error")
	}
}

func TestLoadRun(t *testing.T) {
	p, err := loadRun("../../profiles/runs/web.yaml")
	if err != nil || len(p.Allow) < 3 {
		t.Fatalf("%+v %v", p, err)
	}
}
