package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"adama/event"
	"adama/internal/dnsresult"
	"adama/internal/toolrun"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{Name: "resolve", RequiredTools: []string{"dnsx"}, Kinds: []event.Kind{event.KindDomain, event.KindFQDN},
		Filter:   sdk.Not(sdk.BoundNameRule()),
		Evidence: "DNS address binding",
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, runErr := toolrun.Run(ctx, "dnsx", []string{"-silent", "-a", "-aaaa", "-json"}, strings.NewReader(ev.Value+"\n"))
			evs, err := dnsresult.Parse(out, "resolve", ev.Value)
			return evs, errors.Join(runErr, err)
		}})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
