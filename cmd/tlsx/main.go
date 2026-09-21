package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/toolrun"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		RequiredTools: []string{"tlsx"},
		Name:          "tlsx",
		Kinds:         []event.Kind{event.KindPort},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			u, err := event.PortValue(ev.TargetHost(), ev.Port)
			if err != nil {
				return nil, nil
			}
			args := []string{"-u", u, "-san", "-cn", "-silent", "-nc", "-json"}
			if ev.Name != "" && ev.NameRole == event.NameRequested {
				args = append(args, "-sni", ev.Name)
			}
			out, runErr := toolrun.Run(ctx, "tlsx", args, nil)
			evs, err := parseTLSX(out, ev)
			slog.Info("tlsx", "target", ev.Value, "names", len(evs))
			return evs, errors.Join(runErr, err)
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
