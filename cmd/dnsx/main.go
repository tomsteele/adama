package main

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"adama/event"
	"adama/sdk"
)

func main() {
	words := os.Getenv("DNSX_WORDLIST")
	if words == "" {
		words = "wordlists/dns.txt"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "dnsx",
		Kinds: []event.Kind{event.KindDomain},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, err := exec.CommandContext(ctx, "dnsx", "-d", ev.Value, "-w", words, "-silent").Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("dnsx exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			var evs []event.Event
			sc := bufio.NewScanner(bytes.NewReader(out))
			for sc.Scan() {
				name := event.CanonFQDN(strings.TrimSpace(sc.Text()))
				if name == "" || name == ev.Value {
					continue
				}
				evs = append(evs, event.Event{
					Kind:  event.KindFQDN,
					Value: name,
					Meta:  map[string]string{"parent": ev.Value, "via": "dnsx"},
				})
			}
			slog.Info("dnsx", "domain", ev.Value, "names", len(evs))
			return evs, sc.Err()
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
