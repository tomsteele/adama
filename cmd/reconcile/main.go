package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/reconcile"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var facts *reconcile.Store
	err := sdk.Run(ctx, sdk.Config{Name: "reconcile", Kinds: []event.Kind{event.KindFQDN, event.KindPort}, Observe: true, MaxPending: 1, Filter: reconcile.InputRule(),
		Setup: func(ctx context.Context, b *sdk.Bus) error {
			var err error
			facts, err = reconcile.New(ctx, b.JS)
			return err
		},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, err := facts.Handle(ctx, ev)
			return out, sdk.Retryable(err)
		}})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
