package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/sdk"
)

func main() {
	file := os.Getenv("EXPORT_FILE")
	if file == "" {
		file = "exports/events.jsonl"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "export",
		Kinds: allKinds,
		Handle: func(_ context.Context, ev event.Event) ([]event.Event, error) {
			if err := appendJSONL(file, ev); err != nil {
				return nil, err
			}
			slog.Info("exported", "kind", ev.Kind, "value", ev.Value)
			return nil, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

var allKinds = []event.Kind{
	event.KindDomain,
	event.KindFQDN,
	event.KindNetblock,
	event.KindIP,
	event.KindPort,
	event.KindService,
	event.KindURL,
	event.KindScreenshot,
	event.KindFinding,
}
