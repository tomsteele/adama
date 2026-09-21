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
	"adama/internal/reconcile"
	"adama/internal/toolrun"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{Name: "resolve", RequiredTools: []string{"dnsx"}, Kinds: []event.Kind{event.KindDomain, event.KindFQDN},
		Accept: func(ev event.Event) bool { return !reconcile.BoundName(ev) },
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			if reconcile.BoundName(ev) {
				return nil, nil
			}
			out, runErr := toolrun.Run(ctx, "dnsx", []string{"-silent", "-a", "-aaaa", "-json"}, strings.NewReader(ev.Value+"\n"))
			evs, err := dnsresult.Parse(out, "resolve", ev.Value)
			return evs, errors.Join(runErr, err)
		}})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
