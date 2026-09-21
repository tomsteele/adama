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
	b, err := sdk.Connect(ctx, sdk.NATSURL())
	if err != nil {
		slog.Error("connect", "err", err)
		os.Exit(1)
	}
	defer b.Close()
	facts, err := reconcile.New(ctx, b.JS)
	if err != nil {
		slog.Error("facts", "err", err)
		os.Exit(1)
	}
	err = sdk.Run(ctx, sdk.Config{Name: "reconcile", Kinds: []event.Kind{event.KindFQDN, event.KindPort}, Observe: true, MaxPending: 1, Accept: reconcile.Accept,
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, err := facts.Handle(ctx, ev)
			return out, sdk.Retryable(err)
		}})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
