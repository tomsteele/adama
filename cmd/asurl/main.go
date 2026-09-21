package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/asurl"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:   "as-url",
		Kinds:  []event.Kind{event.KindService},
		Filter: asurl.InputRule(),
		Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
			out, ok := asurl.Event(ev)
			if !ok {
				return nil, nil
			}
			return []event.Event{out}, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
