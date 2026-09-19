package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"adama/event"
	"adama/sdk"
)

func main() {
	kind, value, err := parseArgs(os.Args[1:])
	if err != nil {
		slog.Error("usage: seed <kind> <value> | seed host:port")
		os.Exit(2)
	}
	ev := event.Event{Kind: kind, Value: value, Source: "seed"}
	if err := sdk.Seed(context.Background(), sdk.NATSURL(), ev); err != nil {
		slog.Error("seed", "err", err)
		os.Exit(1)
	}
	slog.Info("seeded", "kind", ev.Kind, "value", ev.Value)
}

func parseArgs(args []string) (event.Kind, string, error) {
	switch len(args) {
	case 1:
		if _, _, err := event.SplitHostPort(args[0]); err != nil {
			return "", "", err
		}
		return event.KindPort, args[0], nil
	case 2:
		return event.Kind(args[0]), args[1], nil
	default:
		return "", "", fmt.Errorf("need kind+value or host:port")
	}
}
