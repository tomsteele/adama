package main

import (
	"context"
	"log/slog"
	"os"

	"adama/event"
	"adama/sdk"
)

func main() {
	if len(os.Args) < 3 {
		slog.Error("usage: seed <kind> <value>")
		os.Exit(2)
	}
	ev := event.Event{Kind: event.Kind(os.Args[1]), Value: os.Args[2], Source: "seed"}
	if err := sdk.Seed(context.Background(), sdk.NATSURL(), ev); err != nil {
		slog.Error("seed", "err", err)
		os.Exit(1)
	}
	slog.Info("seeded", "kind", ev.Kind, "value", ev.Value)
}
