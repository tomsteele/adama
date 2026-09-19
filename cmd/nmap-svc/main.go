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
		Name:  "nmap-svc",
		Kinds: []event.Kind{event.KindPort},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			host, port := ev.Meta["host"], ev.Meta["port"]
			if host == "" || port == "" {
				return nil, nil
			}
			out, err := exec.CommandContext(ctx, "nmap", "-Pn", "-n", "-sV", "-sC", "-p", port, "-oX", "-", host).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nmap-svc exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			svcs, err := nmapx.ParseServices(out)
			if err != nil {
				return nil, err
			}
			slog.Info("nmap-svc", "target", ev.Value, "services", len(svcs))
			return nmapx.ServiceEvents(ev, svcs), nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
