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
		Name:  "nmap",
		Kinds: []event.Kind{event.KindFQDN, event.KindIP},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			out, err := exec.CommandContext(ctx, "nmap", "-Pn", "-n", "-p", "80,443", "-oX", "-", ev.Value).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nmap exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			addrs, ports, err := nmapx.ParseXML(out)
			if err != nil {
				return nil, err
			}
			slog.Info("nmap", "host", ev.Value, "addrs", addrs, "ports", ports)
			return nmapx.Expand(ev, addrs, ports), nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
