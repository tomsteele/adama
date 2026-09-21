package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"adama/event"
	"adama/internal/webprobe"
	"adama/sdk"
)

func main() {
	timeout := 5 * time.Second
	if value := os.Getenv("WEB_PROBE_TIMEOUT"); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			slog.Error("WEB_PROBE_TIMEOUT must be a positive duration")
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{Name: "web-probe", Kinds: []event.Kind{event.KindService}, Filter: webprobe.InputRule(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			return webprobe.Probe(ctx, ev, timeout)
		}})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
