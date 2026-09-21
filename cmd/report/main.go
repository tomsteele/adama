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
	url := os.Getenv("REPORT_URL")
	file := os.Getenv("REPORT_FILE")
	if file == "" {
		file = "reports/events.jsonl"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:       "report",
		Observe:    true,
		MaxPending: 1, // Serialize updates to the file-backed HTML materialization.
		Kinds:      kinds(),
		Setup: func(context.Context, *sdk.Bus) error {
			if url == "" {
				return initFile(file)
			}
			return nil
		},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			if err := deliver(ctx, url, file, ev); err != nil {
				return nil, err
			}
			slog.Info("reported", "kind", ev.Kind, "value", ev.Value)
			return nil, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
