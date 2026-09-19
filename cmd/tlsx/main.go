package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "tlsx",
		Kinds: []event.Kind{event.KindPort},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			if ev.Meta["port"] != "443" {
				return nil, nil
			}
			host := ev.Meta["host"]
			out, err := exec.CommandContext(ctx, "tlsx", "-u", host+":443", "-san", "-cn", "-silent", "-nc", "-json").Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("tlsx exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			evs := parseTLSX(out, ev)
			slog.Info("tlsx", "target", ev.Value, "names", len(evs))
			return evs, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
