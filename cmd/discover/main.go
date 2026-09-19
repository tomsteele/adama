package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/nmapx"
	"adama/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "discover",
		Kinds: []event.Kind{event.KindNetblock},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, err := exec.CommandContext(ctx, "nmap", "-sn", "-oX", "-", ev.Value).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("discover exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			hosts, err := nmapx.ParseDiscovery(out)
			if err != nil {
				return nil, err
			}
			slog.Info("discover", "netblock", ev.Value, "live", len(hosts))
			return nmapx.DiscoverEvents(ev, hosts), nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
