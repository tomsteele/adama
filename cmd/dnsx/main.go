package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/dnsresult"
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
			out, err := exec.CommandContext(ctx, "dnsx", "-d", ev.Value, "-w", words, "-silent", "-a", "-aaaa", "-json").Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("dnsx exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			evs, err := dnsresult.Parse(out, "dnsx", ev.Value)
			slog.Info("dnsx", "domain", ev.Value, "names", len(evs))
			return evs, err
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
