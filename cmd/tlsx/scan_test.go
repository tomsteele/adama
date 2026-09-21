package main

import (
	"context"
	"strings"
	"testing"

	"adama/event"
)

func TestUnsupportedOrInvalidTargetCannotComplete(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		target event.Target
		want   string
	}{
		{event.Target{Host: "192.0.2.1", Port: 443, Proto: event.UDP}, "does not support transport"},
		{event.Target{Host: "192.0.2.1", Port: 0, Proto: event.TCP}, "invalid tlsx target"},
	} {
		out, err := scan(context.Background(), event.Event{Kind: event.KindPort, Target: tc.target})
		if len(out) != 0 || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v %v", out, err)
		}
	}
}
