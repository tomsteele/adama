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
			u, err := event.PortValue(ev.TargetHost(), ev.Port)
			if err != nil {
				return nil, nil
			}
			args := []string{"-u", u, "-san", "-cn", "-silent", "-nc", "-json"}
			if ev.Name != "" && ev.NameRole == event.NameRequested {
				args = append(args, "-sni", ev.Name)
			}
			out, err := exec.CommandContext(ctx, "tlsx", args...).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("tlsx exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			evs, err := parseTLSX(out, ev)
			slog.Info("tlsx", "target", ev.Value, "names", len(evs))
			return evs, err
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
